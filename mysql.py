import pymysql
import threading
from flask import Flask, render_template, request
from dbutils.pooled_db import PooledDB
import plotly.graph_objects as go
import os
class PyMySQLDatabase:
    def __init__(self):
        self.host = '127.0.0.1'
        self.username = 'root'
        self.password = 'root'
        self.database = 'gov110_log'  # 设置数据库名称
        self.db_lock = threading.Lock()
        self.pool = PooledDB(
            creator=pymysql,  # 指定数据库驱动
            host=self.host,
            user=self.username,
            password= self.password,
            database=self.database,
            maxconnections=10,  # 最大连接数
            blocking=True,  # 如果达到最大连接数，是否阻塞等待
            maxcached=10,  # 连接池中最多闲置的连接数
            autocommit=True,  # 自动提交事务
            setsession=[],  # 连接建立后执行的额外操作
            ping=0,  # 检查数据库连接可用性的时间间隔，0表示不检查
        )
        # 建立数据库连接
        try:
            self.connection = self.pool.connection()
            self.cursor = self.connection.cursor()
        except pymysql.Error as e:
            print("数据库连接失败:", str(e))


    def insert_data(self,ip, threat_score, categories, update_time):
        # 插入数据
        with self.db_lock:
            try:
                sql = "INSERT IGNORE INTO gov(ip, threat_score, categories, update_time) VALUES (%s,%s,%s,%s)"
                values = (ip, threat_score, categories, update_time)
                self.cursor.execute(sql, values)
                self.connection.commit()
            except Exception as err:
                print(sql)
                print(values)
                print(f"数据库操作发生错误：{str(err)}")
    def insert_data_all(self,group,intranetIp, ip, threat_score, categories, update_time,log,standardTimestamp):
        # 插入数据
        with self.db_lock:
            try:
                sql = "INSERT IGNORE INTO gov_all(`group`,intranetIp, ip, threat_score, categories, update_time,log,standardTimestamp) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)"
                values = (group,intranetIp, ip, threat_score, categories, update_time,log,standardTimestamp)
                self.cursor.execute(sql, values)
                self.connection.commit()
            except Exception as err:
                print(sql)
                print(values)
                print(f"数据库操作发生错误：{str(err)}")
    def delete_data(self, condition):
        # 删除数据
        sql = "DELETE FROM gov WHERE ip = " + condition
        self.cursor.execute(sql)
        self.connection.commit()

    def update_data(self, condition, new_values):
        # 更新数据
        sql = "UPDATE your_table_name SET " + new_values + " WHERE " + condition
        self.cursor.execute(sql)
        self.connection.commit()

    def select_data(self, condition):
        # 查询数据
        try:
            with self.db_lock:
                sql = "SELECT * FROM gov WHERE ip = '" + condition + "'"
                self.cursor.execute(sql)
                result = self.cursor.fetchone()
                return result
        except Exception as err:
            print(err)
    def select_data_bjos(self, condition):
        # 查询数据
        with self.db_lock:
            sql = "SELECT * FROM bjos WHERE ip = '" + condition + "'"
            self.cursor.execute(sql)
            result = self.cursor.fetchone()
            return result
    def close_connection(self):
        # 关闭数据库连接
        self.cursor.close()
        self.connection.close()
# if __name__ == '__main__':
#     aa = PyMySQLDatabase()
#     ww = "116.193.159.2"
#     ip = aa.select_data_bjos(ww).get('intelligence')
#     # categories=aa.select_data(ww).get('categories')
#     # threat_score=aa.select_data(ww).get("threat_score")
#     # update_time = aa.select_data(ww).get("update_time")
#     print(ip)