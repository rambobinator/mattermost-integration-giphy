# -*- coding: utf-8 -*-
import hashlib
import logging
import os
import re
import sys
import json
from urlparse import urlsplit
from urlparse import urlunsplit

import requests
from flask import Flask
from flask import request
from flask import Response

from mattermost_giphy.settings import *


logging.basicConfig(
    level=logging.INFO, format='[%(asctime)s] [%(levelname)s] %(message)s')
app = Flask(__name__)

@app.route('/')
def root():
    """
    Home handler
    """
    return "OK"

@app.route('/post')
def post_and_close():
    data = {arg: request.args.get(arg) for arg in ("channel", "gif_hash", "hash", "username")}
    m = hashlib.md5()
    m.update("{}{}{}{}".format(data["username"], data["channel"], data["gif_hash"], MATTERMOST_GIPHY_IN_TOKEN))
    _hash = m.hexdigest()
    if _hash == data["hash"]:
        gif_url = "http://media1.giphy.com/media/{}/giphy.gif".format(data['gif_hash'])
        msg = '''`{}` found
        ![Giphy]({})'''.format(data.get('username', 'unknown').title(), gif_url)
        payload = {"username": USERNAME,
                   "icon_url": ICON_URL,
                   "channel": data["channel"],
                   "text": msg}
        r = requests.post(MATTERMOST_GIPHY_IN_TOKEN, json=payload)
    return "<script>close()</script>"


@app.route('/new_post', methods=['POST'])
def new_post():
    """
    Mattermost new post event handler
    """
    try:
        # NOTE: common stuff
        slash_command = False
        resp_data = {}
        resp_data['username'] = USERNAME
        resp_data['icon_url'] = ICON_URL

        data = request.form

        if not 'token' in data:
            raise Exception('Missing necessary token in the post data')

        if MATTERMOST_GIPHY_TOKEN.find(data['token']) == -1:
            raise Exception('Tokens did not match, it is possible that this request came from somewhere other than Mattermost')

        # NOTE: support the slash command
        if 'command' in data:
            slash_command = True
            resp_data['response_type'] = 'in_channel'

        translate_text = data['text']
        
        if not slash_command:
            translate_text = data['text'][len(data['trigger_word']):]

        if not translate_text:
            raise Exception("No translate text provided, not hitting Giphy")

        arguments = translate_text.split()
        help_msg = ""
        if len(arguments) > 1 and "show" in arguments[0]:
            help_msg = ""
            resp_data['response_type'] = "ephemeral"
            translate_text = ' '.join(arguments[1:])
            gif_thumbnail_list = giphy_search(translate_text)
            channel_name = data.get("channel_name")
            user_name = data.get("user_name")
            gif_url = ''
            for thumbnail_url in gif_thumbnail_list:
                gif_hash = re.findall(r'(?<=media/).*?(?=/100.gif)', thumbnail_url)[0]
                m = hashlib.md5()
                m.update("{}{}{}{}".format(user_name, channel_name, gif_hash, MATTERMOST_GIPHY_IN_TOKEN))
                callback_url = "{}post?hash={}&username={}&channel={}&gif_hash={}".format(request.url_root,
                                                                                          m.hexdigest(),
                                                                                          user_name,
                                                                                          channel_name,
                                                                                          gif_hash)
                gif_url += "[![]({} =142x142)]({})".format(thumbnail_url, callback_url)
        else:
            gif_url = giphy_translate(translate_text)

        if not gif_url:
            raise Exception('No gif url found for `{}`'.format(translate_text))

        resp_data['text'] = '''`{}` searched for {} {}
    {}'''.format(data.get('user_name', 'unknown').title(), help_msg, translate_text, gif_url)
    except Exception as err:
        msg = err.message
        logging.error('unable to handle new post :: {}'.format(msg))
        resp_data['text'] = msg
    finally:
        resp = Response(content_type='application/json')
        resp.set_data(json.dumps(resp_data))
        return resp


def giphy_translate(text):
    """
    Giphy translate method, uses the Giphy API to find an appropriate gif url
    """
    try:
        params = {}
        params['s'] = text
        params['rating'] = RATING
        params['api_key'] = GIPHY_API_KEY

        resp = requests.get('{}://api.giphy.com/v1/gifs/translate'.format(SCHEME), params=params, verify=True)

        if resp.status_code is not requests.codes.ok:
            logging.error('Encountered error using Giphy API, text=%s, status=%d, response_body=%s' % (text, resp.status_code, resp.json()))
            return None

        resp_data = resp.json()

        url = list(urlsplit(resp_data['data']['images']['original']['url']))
        url[0] = SCHEME.lower()

        return urlunsplit(url)
    except Exception as err:
        logging.error('unable to translate giphy :: {}'.format(err))
        return None

def giphy_search(text):
    """
    Giphy search method, uses the Giphy API to retrieve appropriate gif thumbnail's url list
    """
    try:
        params = {}
        params['q'] = text
        params['rating'] = RATING
        params['api_key'] = GIPHY_API_KEY
        params['limit'] = GIPHY_SEARCH_LIMIT

        resp = requests.get('{}://api.giphy.com/v1/gifs/search'.format(SCHEME), params=params, verify=True)

        if resp.status_code is not requests.codes.ok:
            logging.error('Encountered error using Giphy API, text=%s, status=%d, response_body=%s' % (text, resp.status_code, resp.json()))
            return None

        return [gif['images']['fixed_height_small']['url'] for gif in resp.json().get('data', [])]

    except Exception as err:
        logging.error('unable to search giphy :: {}'.format(err))
        return None
