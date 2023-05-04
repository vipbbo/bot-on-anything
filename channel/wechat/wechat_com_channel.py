#!/usr/bin/env python
# -*- coding=utf-8 -*-
"""
@time: 2023/4/10 22:24
@Project ：bot-on-anything
@file: wechat_com_channel.py

"""
import time

from channel.channel import Channel
from concurrent.futures import ThreadPoolExecutor
from common.log import logger
from config import conf

from wechatpy.enterprise.crypto import WeChatCrypto
from wechatpy.enterprise import WeChatClient
from wechatpy.exceptions import InvalidSignatureException
from wechatpy.enterprise.exceptions import InvalidCorpIdException
from wechatpy.enterprise import parse_message
from flask import Flask, request, abort, make_response
import xml.etree.ElementTree as ET
import datetime
import hashlib
thread_pool = ThreadPoolExecutor(max_workers=8)
app = Flask(__name__)


@app.route('/wechat', methods=['GET', 'POST'])
def handler_msg():
    logger.info("-----wechat-----")
    return WechatEnterpriseChannel().handle()


_conf = conf().get("channel").get("wechat_com")


class WechatEnterpriseChannel(Channel):
    def __init__(self):
        self.CorpId = _conf.get('wechat_corp_id')
        self.Secret = _conf.get('secret')
        self.AppId = _conf.get('appid')
        self.TOKEN = _conf.get('wechat_token')
        self.EncodingAESKey = _conf.get('wechat_encoding_aes_key')
        self.crypto = WeChatCrypto(self.TOKEN, self.EncodingAESKey, self.CorpId)
        self.client = WeChatClient(self.CorpId, self.Secret, self.AppId)

    def startup(self):
        # start message listener
        app.run(host='0.0.0.0', port=_conf.get('port'))

    def send(self, msg, receiver):
        # 切片长度
        n = 450
        if len(msg) < n:
          logger.info('[WXCOM] sendMsg={}, receiver={}'.format(msg, receiver))
          self.client.message.send_text(self.AppId, receiver, msg)
          return
        # 分割后的子字符串列表
        chunks = [msg[i:i+n] for i in range(0, len(msg), n)]
        # 总消息数
        total = len(chunks)
        # 循环发送每个子字符串
        for i, chunk in enumerate(chunks):
            logger.info('[WXCOM] sendMsg={}, receiver={}, page_number={}, page_total={}'.format(msg, chunk, i+1, total))
            self.client.message.send_text(self.AppId, receiver, chunk)
            time.sleep(1) # 用延迟的方式使微信插件的输出顺序正常

    def _do_send(self, query, reply_user_id):
        try:
            if not query:
                return
            context = dict()
            context['from_user_id'] = reply_user_id
            reply_text = super().build_reply_content(query, context)
            if reply_text:
                self.send(reply_text, reply_user_id)
        except Exception as e:
            logger.exception(e)

    def handle(self):
        query_params = request.args
        signature = query_params.get('msg_signature', '')
        timestamp = query_params.get('timestamp', '')
        nonce = query_params.get('nonce', '')
        if request.method == "GET":
            # Handle verification request from WeChat server
            signature = request.args.get("signature")
            timestamp = request.args.get("timestamp")
            nonce = request.args.get("nonce")
            echostr = request.args.get("echostr")
            token = "paidaxing_token"  # 修改为您在微信公众平台中设置的 Token 值
            array = [token, timestamp, nonce]
            array.sort()
            temp_str = "".join(array)
            sha1_str = hashlib.sha1(temp_str.encode()).hexdigest()

            if sha1_str == signature:
                # 在处理微信服务器发送的验证请求时，您需要返回一个包含验证字符串的响应。具体地，您需要按照如下格式设置响应头和响应内容：
                # 其中，<length> 是 <echostr> 的长度，<echostr> 是由微信服务器生成的随机字符串。请注意，这个响应的 content-type 应该为 text/plain。
                # 在 Flask 中，您可以使用以下代码来设置响应头和响应内容：
                resp = make_response(echostr)
                resp.headers["Content-Type"] = "text/plain"
                return resp

                # return echostr
            else:
                return ""
        elif request.method == "POST":

            try:
                message = self.crypto.decrypt_message(
                    request.data,
                    signature,
                    timestamp,
                    nonce
                )
            except (InvalidSignatureException, InvalidCorpIdException):
                abort(403)
            msg = parse_message(message)
            if msg.type == 'text':
                thread_pool.submit(self._do_send, msg.content, msg.source)
            else:
                now = datetime.datetime.now()
                print("Current date and time: ", now)

                # Handle user click event on menu
                data = request.data
                xml_data = ET.fromstring(data)
                from_user_name = xml_data.find("FromUserName").text
                to_user_name = xml_data.find("ToUserName").text
                event_type = xml_data.find("Event").text

                if event_type == "CLICK":
                    event_key = xml_data.find("EventKey").text

                    if event_key == "V1001_PERSON_INFO":
                        # TODO: Execute corresponding operation for menu item 1
                        response_str = "You clicked menu item 1!"
                        content = "个人信息\n角色：言小宝\n音色：小宝\n回复方式：仅文字\n余额：10次"
                    elif event_key == "menu_item_2":
                        # TODO: Execute corresponding operation for menu item 2
                        response_str = "You clicked menu item 2!"
                    else:
                        response_str = "Unknown menu item!"
                else:
                    response_str = "Invalid event type"


            # resp = make_response(response_str)
            # resp.content_type = "application/xml"
            escaped_response_str = content.replace("<br/>", "&lt;br/&gt;")
            response_str = "<xml><ToUserName><![CDATA[%s]]></ToUserName><FromUserName><![CDATA[%s]]></FromUserName><CreateTime>%s</CreateTime><MsgType><![CDATA[text]]></MsgType><Content><![CDATA[%s]]></Content></xml>"
            resp = make_response(response_str % (from_user_name, to_user_name, now, escaped_response_str))
            resp.content_type = "application/xml"
            return resp
        else:
            # Invalid request method
            return ""
