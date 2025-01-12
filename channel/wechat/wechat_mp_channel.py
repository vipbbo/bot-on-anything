import werobot
import time
from config import channel_conf
from common import const
from common.log import logger
from channel.channel import Channel
from concurrent.futures import ThreadPoolExecutor
from flask import request, jsonify
import os

import collections

import sqlite3
import threading

# 创建互斥锁对象
lock = threading.Lock()

# 连接到 SQLite3 数据库文件
conn = sqlite3.connect('paidaxing_mp.db', timeout=10, check_same_thread=False)
c = conn.cursor()


# 连接到 SQLite3 数据库文件
def init_db():
    # # 连接到 SQLite3 数据库文件
    # conn = sqlite3.connect('paidaxing_mp.db', timeout=10, cached_statements=False)
    # c = conn.cursor()

    # 检查 users 表格是否存在
    query = "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"
    result = c.execute(query)
    # 如果不存在则新建表格
    if not result.fetchone():
        # 执行 SQL 建表语句
        # 使用线程锁来保证同一时间只能有一个线程访问数据库
        with lock:
            c.execute('''CREATE TABLE users
                         (user_id TEXT PRIMARY KEY,
                          visit_count INTEGER NOT NULL DEFAULT 0,
                          limit_count INTEGER NOT NULL DEFAULT 10)''')

    # 提交事务并关闭连接
    conn.commit()
    # conn.close()


# 记录用户访问chatGPT事件的次数
def mark_chatGPT_count(user_id):
    with lock:
        # userId: 访问人的ID 0: 初始化访问次数  10: 一共可访问的次数
        c.execute('INSERT OR IGNORE INTO users (user_id, visit_count, limit_count) VALUES (?, ?, ?)',
                  (user_id, 0, 10))
    conn.commit()


# 处理用户访问事件
def handle_wechat_request(user_id):
    with lock:
        # 更新用户访问次数
        c.execute('UPDATE users SET visit_count = visit_count + 1 WHERE user_id = ?', (user_id,))
    conn.commit()


# 提供获取用户最大访问次数的 API 接口
def get_limit_count(user_id):
    with lock:
        c.execute('SELECT limit_count FROM users WHERE user_id = ?', (user_id,))
        # 处理查询结果
        result = c.fetchone()
        if result is not None:
            count = result[0]
        else:
            count = 0
        # count = c.fetchone()[0]
    return count
    # return jsonify(visit_count=count)


# 提供获取用户已经访问次数的 API 接口
def get_visit_count(user_id):
    with lock:
        c.execute('SELECT visit_count FROM users WHERE user_id = ?', (user_id,))
        # 处理查询结果
        result = c.fetchone()
        if result is not None:
            count = result[0]
        else:
            count = 0
        # count = c.fetchone()[0]
    return count
    # return jsonify(visit_count=count)


# ---------------------分割线


class RateLimitException(Exception):
    pass


def rate_limiter(limit):
    counts = collections.defaultdict(lambda: collections.Counter())

    def decorate(func):
        def call(user_id, *args, **kwargs):
            api_name = func.__name__
            user_counts = counts[user_id]

            user_counts[api_name] += 1

            if user_counts[api_name] > limit:
                raise RateLimitException(f"User {user_id} has exceeded the rate limit of {limit} for API {api_name}")

            return func(user_id, *args, **kwargs)

        return call

    return decorate


@rate_limiter(10)
def limit_api(user_id):
    print(f"Example API called for user {user_id}")


robot = werobot.WeRoBot(token=channel_conf(const.WECHAT_MP).get('token'))
thread_pool = ThreadPoolExecutor(max_workers=8)
cache = {}


# 处理新用户订阅事件，并初始化其访问CHATGPT的次数
@robot.subscribe
def on_subscribe(message):
    user_id = message.source
    # 在数据库中插入新用户信息
    mark_chatGPT_count(user_id)
    conn.commit()
    return "欢迎关注我的公众号！"


@robot.text
def hello_world(msg):
    try:
        limit_count = get_limit_count(msg.source)
        visit_count = get_visit_count(msg.source)
        if visit_count > limit_count:
            return "您的免费额度只有 " + str(limit_count) + " 次。"
        rate_limiter(limit_count)
        # limit_api(msg.source)
    except RateLimitException as e:
        return "您的免费额度只有10次。"
    with open('sensitive_words.txt', 'r', encoding='utf-8') as f:  # 加入检测违规词
        sensitive_words = [line.strip() for line in f.readlines()]
        found = False
        for word in sensitive_words:
            if word != '' and word in msg.content:
                found = True
                break
        if found:
            return "输入内容有敏感词汇"

        else:
            logger.info('[WX_Public] receive public msg: {}, userId: {}, '.format(msg.content, msg.source))
            key = msg.content + '|' + msg.source
            if cache.get(key):
                # request time
                cache.get(key)['req_times'] += 1
            return WechatSubsribeAccount().handle(msg)


@robot.click
def V1001_PERSON_INFO(msg):
    logger.info('[WX_Public] click event msg.type: {}, userId: {}'.format(msg.type, msg.source))
    logger.info('[WX_Public] receive public msg.key:{}'.format(msg.key))
    if msg.key == "V1001_PERSON_INFO":
        return "个人信息\n角色：言小宝\n音色：小宝\n回复方式：仅文字\n余额：" + str(
            get_limit_count(msg.source) - get_visit_count(msg.source)) + "次!"


@robot.click
def V1002_CLEAR_INFO(msg):
    logger.info('[WX_Public] click event msg.type: {}, userId: {}'.format(msg.type, msg.source))
    logger.info('[WX_Public] click event msg.key:{}'.format(msg.key))
    if msg.key == "V1002_CLEAR_INFO":
        msg.content = "#清除记忆"
        return WechatSubsribeAccount().handle(msg)

    # return WechatServiceAccount().handle(msg)


class WechatSubsribeAccount(Channel):
    def startup(self):
        logger.info('[WX_Public] Wechat Public account service start!')
        robot.config['PORT'] = channel_conf(const.WECHAT_MP).get('port')
        robot.config['HOST'] = '0.0.0.0'
        init_db()
        robot.run()

    def handle(self, msg, count=1):
        # handle_wechat_request(msg.source)
        if msg.content == "继续":
            return self.get_un_send_content(msg.source)

        context = dict()
        context['from_user_id'] = msg.source
        key = msg.content + '|' + msg.source
        res = cache.get(key)
        if not res:
            cache[key] = {"status": "waiting", "req_times": 1}
            thread_pool.submit(self._do_send, msg.content, context)

        res = cache.get(key)
        logger.info("count={}, res={}".format(count, res))
        if res.get('status') == 'success':
            res['status'] = "done"
            cache.pop(key)
            return res.get("data")

        if cache.get(key)['req_times'] == 3 and count >= 4:
            logger.info("微信超时3次")
            return "已开始处理，请稍等片刻后输入\"继续\"查看回复"

        if count <= 5:
            time.sleep(1)
            if count == 5:
                # 第5秒不做返回，防止消息发送出去了但是微信已经中断连接
                return None
            return self.handle(msg, count + 1)

    def _do_send(self, query, context):
        handle_wechat_request(context['from_user_id'])
        key = query + '|' + context['from_user_id']
        reply_text = super().build_reply_content(query, context)
        logger.info('[WX_Public] reply content: {}'.format(reply_text))
        cache[key]['status'] = "success"
        cache[key]['data'] = reply_text

    def get_un_send_content(self, from_user_id):
        for key in cache:
            if from_user_id in key:
                value = cache[key]
                if value.get('status') == "success":
                    cache.pop(key)
                    return value.get("data")
                return "还在处理中，请稍后再试"
        return "目前无等待回复信息，请输入对话"
