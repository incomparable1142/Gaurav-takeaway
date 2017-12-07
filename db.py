from pymongo import MongoClient
from flask import jsonify
import traceback
import json
import datetime
from bson import ObjectId


class Mdb:

    def __init__(self):
        conn_str = 'mongodb://tuser:tpass@ds133166.mlab.com:33166/' \
                   'takeaway'
        client = MongoClient(conn_str)
        self.db = client['takeaway']
        print("[Mdb] connected to database :: ", self.db)

############################################################################
#                                                                          #
#                              USER PANEL                                  #
#                                                                          #
############################################################################

    def check_email(self, email):
        return self.db.user.find({'email': email}).count() > 0


############################################################################
#                                                                          #
#                       REGISTRATION USRE IN DATABASE                      #
#                                                                          #
############################################################################
    def add_user(self, name, email, pw_hash, age, phone, address, gender):
        try:
            rec = {
                'name': name,
                'email': email,
                'password': pw_hash,
                'age': age,
                'phone': phone,
                'address': address,
                'gender': gender
            }
            self.db.user.insert(rec)

        except Exception as exp:
            print("add_user() :: Got exception: %s", exp)
            print(traceback.format_exc())

############################################################################
#                                                                          #
#        CHECK EMAIL EXIST OR NOT IN DATABASE BEFORE LOGIN CANDIDATE       #
#                                                                          #
############################################################################
    def user_exists(self, email):
        return self.db.user.find({'email': email}).count() > 0

############################################################################
#                                                                          #
#                   MATCH PASSWORD AND EMAIL THEN LOGIN                    #
#                                                                          #
############################################################################
    def get_password(self, email):
        result = self.db.user.find({'email': email})
        name = ''
        password = ''
        if result:
            for data in result:
                name = data['name']
                password = data['password']
                print('password in db class', password)
        return password

############################################################################
#                                                                          #
#                GET NAME AND EMAILID VIA EMAIL ADDRESS                    #
#                                                                          #
############################################################################
    def get_name(self, email):
        result = self.db.user.find({'email': email})
        name = ''
        email = ''
        if result:
            for data in result:
                name = data['name']
                email = data['email']
        return name


#############################################
#                                           #
#         GET USER ID BY SESSION            #
#                                           #
#############################################
    def get_user_id_by_session(self, email):
        result = self.db.user.find({'email': email})
        id = ''
        if result:
            for data in result:
                id = data['_id']
        return id

############################################################################
#                                                                          #
#                        CANDIDATE SESSION INFORMATION                     #
#                                                                          #
############################################################################
    def save_login_info(self, user_email, mac, ip, user_agent, type):
        LOGIN_TYPE = 'User Login'
        try:
            ts = datetime.datetime.today().strftime("%a %b %d %X  %Y ")

            rec = {
                'user_id': user_email,
                'mac': mac,
                'ip': ip,
                'user_agent': user_agent,
                'user_type': type,
                'timestamp': ts
            }

            self.db.user_session.insert(rec)
        except Exception as exp:
            print("save_login_info() :: Got exception: %s", exp)
            print(traceback.format_exc())


############################################################################
#                                                                          #
#                              MAIN                                        #
#                                                                          #
############################################################################
if __name__ == "__main__":
    mdb = Mdb()
    # mdb.add_admin('john@gmail.com', '123')
