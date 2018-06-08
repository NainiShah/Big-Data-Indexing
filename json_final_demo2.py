# -*- coding: utf-8 -*-
"""
Created on Sat Mar 24 02:09:39 2018

@author: lobof
"""

import json
from jsonschema import validate
from jsonschema import Draft3Validator
from flask import Flask
from flask import jsonify
from flask import request, Response
import uuid
import os
import jwt
import datetime
import time
#from flask_security import auth_token_required
from flask import jsonify
from werkzeug.security import safe_str_cmp
from flask import make_response
from hashlib import md5
# REST API
app = Flask(__name__)   
import ast
import hashlib

import redis
conn = redis.Redis('localhost',charset="utf-8", decode_responses=True)

os.getcwd()
os.chdir("C:\\NU\\Big_Data")


conn = redis.Redis('localhost',charset="utf-8", decode_responses=True)

@app.route('/orgdb/product/upload_file/', methods=['POST'])
def upload_file():
        for header in request.headers:
            print(header)

        data = request.get_json()   
        with open(r'''usecase_schema.json''') as json_schema:   
            schema = json.load(json_schema)
                                       
        myJSONValidation = Draft3Validator(schema).is_valid(data) 
        if(myJSONValidation == True):
            for key,value in data.items():
                if type(value) is dict:
                    dUId = uuid.uuid4()
                    dUId = str(dUId)
                    value['uuid'] = dUId
                    value2 = json.dumps(value)
                    conn.set(dUId, value2)
                    print('Dict',key)
                    print(conn.get(dUId))
                    print()
                    #conn.set(key, dUId)
                    data[key] = dUId
#                    print(key)
#                    print(dUId)

                elif type(value) is list:
                    print("Inside list",key)
                    for i,x in enumerate(value):
                        if(type(x) is dict):
                            sUId = uuid.uuid4()
                            sUId = str(sUId)
                            x['uuid']= sUId
                            x2 = json.dumps(x)
                            conn.set(sUId,x2)
                            print('Dict',i)
                            print(conn.get(sUId))
                            print()
                            value[i] = sUId                          

                else:
                    conn.set(key,value)
#
#                
#        
            uniqueId = uuid.uuid4()
            encoded = jwt.encode({'exp': datetime.datetime.utcnow() + 
                                      datetime.timedelta(seconds=36000)}, 'secret')
            
            #encoded=str(encoded)
            token = encoded.decode('utf-8')
            print(type(token))
            
            response = make_response(jsonify(data), 200)
            response.headers["ETag"] = str(hashlib.sha256("data".encode('utf-8')).hexdigest())
            response.headers["Cache-Control"] = "private, max-age=300"
            print('etag', response.headers["ETag"])
            
        #return response
            uniqueId = str(uniqueId)
            data['token'] = token
            data['uuid'] = uniqueId
            #data['etag'] = response.headers["ETag"]
            data2 = json.dumps(data)
            
            conn.set(uniqueId, data2)
            
        
            print()
            print(uniqueId , ":")
            print('token','\n',token)
            print(conn.get(uniqueId))
           
            return jsonify({"product": data2}) 

        else:
            return "JSON was not validated by the schema"
        
# updating a record
@app.route('/orgdb/product/upload_file/<myuuid>',methods=['PUT'])
def updateProduct(myuuid): 
    data = request.get_json()
    data = json.dumps(data)
    data = json.loads(data)
    data2 = conn.get(myuuid)
    data2 = json.loads(data2)
    print(data2, type(data2))
       
   
    try:   
        jwt.decode(data2["token"], 'secret', leeway=10, algorithms=['HS256'],verify= True)
    except jwt.ExpiredSignatureError:
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'
#    except Exception as e:
#        print("Token Expired")
#        return jsonify({'Token Expired'})
    encoded = 'Bearer ' + data2["token"]
    print("Encoded ", encoded)
    print(type(encoded))
    print(request.headers["Authorization"])
    print(type(request.headers["Authorization"]))
    if (request.headers['Authorization'] != encoded):
        return "Authorization Error"
        print(data)
        print(type(data))
         #Loading Schema        
    with open(r'''usecase_schema.json''') as json_schema:    
        schema = json.load(json_schema)
        
        #validating data against schema        
        
        myJSONValidation = Draft3Validator(schema).is_valid(data)
        if(myJSONValidation == True):
            
            for key,value in data2.items():
                #print(value)
                if conn.exists(value) and str(key) not in ['uuid']:
                    #print("Value exists in redis")
                    redisValue = conn.get(value)
                    redisValue = json.loads(redisValue)
                    data2[key] = redisValue

                elif type(value) is list:
                    #print("Inside list",key)
                    for i,x in enumerate(value):
                        #print(x)
                        if(conn.exists(x) and key is not 'uuid'):
                            #print("Dict exists in redis")
                            redisValue = conn.get(x)
                            redisValue = str(redisValue)
                            value[i] = redisValue

                else:
                    conn.set(key,value)
#
#                
#        
            
            #conn.hmset(uuid, data)
            #print()
            #print(uuid , ":")
            #print(conn.hgetall(uuid))
            data2 = json.dumps(data2)
            data2 = json.loads(data2)
            data = json.dumps(data)
            data = json.loads(data)
            print()
            print("Data after get",data2)
            print()

            keyCount = 0
            for (keyData,valueData),(keyRedis,valueRedis) in zip(data.items(),data2.items()):
                if type(valueData) is dict and keyData in data2:
                    dUId = valueRedis['uuid']
                    dUId = str(dUId)
                    valueData['uuid'] = dUId
                    value2 = json.dumps(valueData)
                    conn.set(dUId, value2)
                    print('Dict',keyData)
                    print(conn.get(dUId))
                    print()
                    #conn.set(key, dUId)
                    data[keyData] = dUId
                elif type(valueData) is dict and keyData not in data:
                    dUId = uuid.uuid4()
                    dUId = str(dUId)
                    valueData['uuid'] = dUId
                    value2 = json.dumps(valueData)
                    conn.set(dUId, value2)
                    print('Dict',keyData)
                    print(conn.get(dUId))
                    print()
                    #conn.set(key, dUId)
                    data[keyData] = dUId
                        
                elif type(valueData) is list and type(valueRedis) is list:
                    for (iData,xData),(iRedis,xRedis) in zip(enumerate(valueData),enumerate(valueRedis)):
                        #print(xRedis)
                        xRedis = ast.literal_eval(xRedis)
                        if(type(xData) is dict and len(xRedis) - len(xData) == 1):
                            print("Same Data")
                            sUId = xRedis['uuid']
                            sUId = str(sUId)
                            xData['uuid']= sUId
                            x2 = json.dumps(xData)
                            conn.set(sUId,x2)
                            print('Dict',iData)
                            print(conn.get(sUId))
                            print()
                            valueData[iData] = sUId
                            keyCount = keyCount + 1
                        else:
                            print("Different Data")
                            sUId = uuid.uuid4()
                            sUId = str(sUId)
                            valueData[keyCount]['uuid']= sUId
                            x2 = json.dumps(xData)
                            conn.set(sUId,x2)
                            print('Dict',iData)
                            print(conn.get(sUId))
                            print()
                            valueData[keyCount] = sUId 
                            
                        
            uniqueId = data2['uuid']
            uniqueId = str(uniqueId)
            data['uuid'] = uniqueId
            only_token = data2["token"]
            only_token = str(only_token)
            data['token'] = only_token
            data3 = json.dumps(data)

       
            
            if request.method == 'PUT':
                old_etag = request.headers.get('If-None-Match', '')
            # Generate hash
            #data = json.dumps(data3)
            new_etag = md5(data3.encode('utf-8')).hexdigest()

            if new_etag == old_etag:
                # Resource has not changed
                return '', 304
            else:
                conn.set(uniqueId, data3)
                print()
                #print(uniqueId , ":")
                print("Unique ID",uniqueId)
                print("Data after update:")
                print(data3)
                # Resource has changed, send new ETag value
                return jsonify({'product': data3}),200, {'ETag': new_etag}
  
            
            
#            return jsonify(data) 

        else:
            return "JSON was not validated by the schema"
        
@app.route('/orgdb/product/<uuid>',methods=['GET'])
def getAllProducts(uuid):
    for header in request.headers:
            print(header)
    data2 = conn.get(uuid)
    data2 = json.loads(data2)
    print(data2)
    try:   
        jwt.decode(data2["token"], 'secret', leeway=10, algorithms=['HS256'],verify= True)
    except jwt.ExpiredSignatureError:
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'
#    except Exception as e:
#        print("Token Expired")
#        return jsonify({'Token Expired'})
    encoded = 'Bearer ' + data2["token"]
    print("Encoded ", encoded)
    print(type(encoded))
    print(request.headers["Authorization"])
    print(type(request.headers["Authorization"]))
    if (request.headers['Authorization'] != encoded):
        return "Authorization Error"
   
    for key,value in data2.items():
                #print(value)
                if conn.exists(value) and str(key) not in ['uuid']:
                    #print("Value exists in redis")
                    redisValue = conn.get(value)
                    redisValue = json.loads(redisValue)
                    data2[key] = redisValue

                elif type(value) is list:
                    #print("Inside list",key)
                    for i,x in enumerate(value):
                        #print(x)
                        if(conn.exists(x) and key is not 'uuid'):
                            #print("Dict exists in redis")
                            redisValue = conn.get(x)
                            redisValue = str(redisValue)
                            value[i] = redisValue

                else:
                    conn.set(key,value)
#
#                
#        
            
            #conn.hmset(uuid, data)
            #print()
            #print(uuid , ":")
            #print(conn.hgetall(uuid))
    data2 = json.dumps(data2)
    data2 = json.loads(data2)

    print()
    print("Data after get",data2)
    print()

      #JWT payload is now expired
      #But with some leeway, it will still validate
   
    if request.method == 'GET':
            old_etag = request.headers.get('If-None-Match', '')
            # Generate hash
            data = json.dumps(data2)
            new_etag = md5(data.encode('utf-8')).hexdigest()

            if new_etag == old_etag:
                # Resource has not changed
                return '', 304
            else:
                # Resource has changed, send new ETag value
                return jsonify({'product': data2}),200, {'ETag': new_etag}
    return 'test'

@app.route('/orgdb/product/upload_file/updateAll/<uuid>', methods=['PUT'])
def updateALL_product(uuid):
    for header in request.headers:
            print(header)
    data = request.get_json()
    data = json.dumps(data)
    data = json.loads(data)
    data2 = conn.get(uuid)
    data2 = json.loads(data2)
    print(data2)
    print()
    print(data)
    print()
    try:   
        jwt.decode(data2["token"], 'secret', leeway=10, algorithms=['HS256'],verify= True)
    except jwt.ExpiredSignatureError:
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'
#    except Exception as e:
#        print("Token Expired")
#        return jsonify({'Token Expired'})
    encoded = 'Bearer ' + data2["token"]
    
    if (request.headers['Authorization'] != encoded):
        return "Authorization Error"
#        print(data)
#        print(type(data))
        # Loading Schema 
    with open(r'''schema.txt''') as json_schema:   
        schema = json.load(json_schema)
        
        #validating data against schema        
        
    myJSONValidation = Draft3Validator(schema).is_valid(data)
    if(myJSONValidation == True):
        uniqueId = data2['uuid']
        uniqueId = str(uniqueId)
        data['uuid'] = uniqueId
        only_token = data2["token"]
        only_token = str(only_token)
        data['token'] = only_token
        data3 = json.dumps(data)

        if request.method == 'PUT':
            old_etag = request.headers.get('If-None-Match', '')
            # Generate hash
#            data_n = json.dumps(data2)
            new_etag = md5(data3.encode('utf-8')).hexdigest()

            if new_etag == old_etag:
                # Resource has not changed
                return '', 304
            else:
                conn.set(uuid,data3)
                return jsonify({'product': data}),200, {'ETag': new_etag}
    return 'test'

        
   # return jsonify(data)
@app.route('/orgdb/product/<uuid>',methods=['DELETE'])
def deleteAllProducts(uuid): 
    redData = conn.get(uuid)
    redData = json.loads(redData)
    try:   
        jwt.decode(redData["d_encoded"], 'secret', leeway=10, algorithms=['HS256'],verify= True)
    except jwt.ExpiredSignatureError:
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'
    encoded = 'Bearer ' + redData["d_encoded"]
    if (request.headers['Authorization'] != encoded):
        return "Authorization Error"
    
    if request.method == 'DELETE':
            old_etag = request.headers.get('If-None-Match', '')
            # Generate hash
            data = json.dumps(redData)
            new_etag = md5(data.encode('utf-8')).hexdigest()

            if new_etag == old_etag:
                # Resource has not changed
                if not bool(redData):
                    return "product set does not exist"
                else:
                    conn.delete(uuid)     
                    return jsonify({'response':'Success'})
               # return '', 304
            else:
                # Resource has changed, send new ETag value
                return 200, {'ETag': new_etag}
    return 'test'
    
#    if not bool(redData):
#        return "product set does not exist"
#    else:
#        conn.delete(uuid)     
#        return jsonify({'response':'Success'})

        
   # return jsonify(data)

        

if __name__ == '__main__':
# app.debug = True
 app.run(host = '0.0.0.0', port = 8090)
 
 
 
