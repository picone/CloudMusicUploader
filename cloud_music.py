# -*- encoding=utf-8 -*-
import hashlib
import json
import pickle
import random
import urllib3
import uuid
from Crypto.Cipher import AES
from binascii import b2a_hex
from urllib import parse


class API:
    """
    网易云音乐API调用
    """
    _default_headers = {
        'Accept': '*/*',
        'Origin': 'orpheus://orpheus',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/605.1.15 (KHTML, like Gecko)',
        'Accept-language': 'zh-cn',
        'Accept-encoding': 'gzip, deflate',
    }
    _user_id = 0

    def __init__(self, num_pools=5, proxy=None):
        """初始化urllib
        :param int num_pools: 线程数量
        :param str proxy: 代理地址
        """
        self._cookie = Cookie(default_cookie={
            'appver': '1.5.9',
            'channel': 'netease',
            'os': 'osx',
            'osver': '版本 10.13.6（版号 17G65）',
        })
        # 若没有deviceId则生成一个
        if self._cookie.get_cookie('deviceId') is None:
            self._cookie['deviceId'] = generate_device_id()
        # 禁用https不安全警告
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        if proxy is None:
            self.__http_pool = urllib3.PoolManager(num_pools, self._default_headers)
        else:
            self.__http_pool = urllib3.ProxyManager(proxy, num_pools, self._default_headers)

    def login(self, username, password, login_type):
        m = hashlib.md5()
        m.update(password.encode())
        params = {
            'username': username,
            'password': m.hexdigest(),
            'type': str(login_type),
            'remember': 'true',
            'https': 'true',
            'e_r': True,
        }
        resp = self._request_eapi('/eapi/login', b'/api/login', params, True)
        if resp is not None and resp['code'] == 200:
            return {
                'account': resp['account'],
                'profile': resp['profile'],
            }
        return None

    def refresh_token(self):
        """
        cookie续命
        :return bool: 是否刷新成功
        """
        music_u = self._cookie.get_cookie('MUSIC_U')
        if music_u is None:
            return False
        params = {
            'cookieToken': music_u,
        }
        resp = self._request_eapi('/eapi/login/token/refresh', b'/api/login/token/refresh', params)
        if resp is not None and resp['code'] == 200:
            return True
        else:
            return False

    def user_info(self):
        """
        获取用户信息
        :return dict:
        """
        resp = self._request_eapi('/eapi/v1/user/info', b'/api/v1/user/info', {})
        return resp

    def get_all_user_playlist(self, uid=None):
        """
        获取用户所有歌单
        :param int uid: 用户ID
        :return list: 歌单列表
        """
        offset = 0
        limit = 1000
        ret = []
        while True:
            resp = self.user_playlist(uid, offset, limit)
            if resp is None:
                break
            else:
                ret.extend(resp['playlist'])
                if not resp['more']:
                    break
            offset += limit
        return ret

    def user_playlist(self, uid=None, offset=0, limit=1000):
        """
        获取用户歌单
        :param int uid: 用户ID，默认当前登录用户
        :param int offset:
        :param int limit:
        :return:
        """
        if uid is None:
            uid = self._user_id
        params = {
            'uid': uid,
            'limit': limit,
            'offset': offset,
        }
        resp = self._request_eapi('/eapi/user/playlist', b'/api/user/playlist', params)
        if resp is not None and 'code' in resp and resp['code'] == 200:
            return resp
        return None

    def get_all_play_list_detail(self, play_list_id):
        """
        获取歌单内所有歌曲详情
        :param play_list_id: 歌单ID
        :return list:
        """
        limit = 500
        resp = self.play_list_detail(play_list_id, 0, limit)
        if resp is None:
            return []
        ret = resp['playlist']['tracks']
        track_ids = resp['playlist']['trackIds']
        for offset in range(len(ret), len(track_ids), limit):
            song_ids = list(map(lambda x: x['id'], track_ids[offset: offset+limit]))
            resp = self.song_detail(song_ids)
            if resp is not None:
                ret.extend(resp['songs'])
        return ret

    def play_list_detail(self, play_list_id, limit=1000, offset=0):
        """
        获取歌单列表详情
        :param int play_list_id: 歌单ID
        :param int limit: 获取tracks数量
        :param int offset: offset
        :return dict:
        """
        params = {
            'id': str(play_list_id),
            'c': '[]',
            't': '-1',
            'n': str(limit),  # tracks数量
            's': str(offset),
        }
        resp = self._request_eapi('/eapi/v3/playlist/detail', b'/api/v3/playlist/detail', params)
        if resp is not None and 'code' in resp and resp['code'] == 200:
            return resp
        return None

    def song_detail(self, song_ids):
        """
        歌曲详情
        :param song_ids:
        :return:
        """
        c = list(map(lambda x: {'id': x, 'v': 0}, song_ids))
        params = {
            'c': json.dumps(c, separators=(',', ':')),
            'rv': 'true',
        }
        resp = self._request_eapi('/eapi/v3/song/detail', b'/api/v3/song/detail', params)
        if resp is not None and 'code' in resp and resp['code'] == 200:
            return resp
        return None

    def player_url(self, song_ids, bit_rate=320000):
        """
        获取播放地址
        :param tuple(str) song_ids: 歌曲ID列表
        :param int bit_rate: 歌曲码率
        :return dict:
        """
        params = {
            'ids': json.dumps(song_ids, separators=(',', ':')),
            'br': str(bit_rate),
            'e_r': True
        }
        resp = self._request_eapi('/eapi/song/enhance/player/url', b'/api/song/enhance/player/url', params, True)
        if resp is not None and 'code' in resp and resp['code'] == 200:
            return resp['data']
        return None

    def cloud_upload_check(self, md5, length, bit_rate, ext):
        """
        上传前检查，获取songId
        :param str md5: 文件MD5
        :param int length: 文件大小(byte)
        :param int bit_rate: 音乐码率
        :param str ext: 扩展名
        :return dict:
        """
        params = {
            'md5': md5,
            'length': str(length),
            'bitrate': str(bit_rate),
            'ext': ext,
            'version': '1',
        }
        resp = self._request_eapi('/eapi/cloud/upload/check', b'/api/cloud/upload/check', params)
        if resp is not None and 'code' in resp and resp['code'] == 200:
            return resp
        return None

    def cloud_upload_info(self, md5, song_id, filename, song, artist, bit_rate):
        """
        设置上传文件的信息
        :param md5: 文件MD5
        :param song_id: 歌曲ID
        :param filename: 文件名
        :param song: 歌曲名
        :param artist: 艺术家名
        :param bit_rate: 码率
        :return dict:
        """
        params = {
            'md5': md5,
            'songid': song_id,
            'filename': filename,
            'song': song,
            'artist': artist,
            'bitrate': bit_rate,
        }
        resp = self._request_eapi('/eapi/upload/cloud/info/v2', b'/api/upload/cloud/info/v2', params)
        if resp is not None and 'code' in resp and resp['code'] == 200:
            return resp
        return None

    def cloud_publish(self, song_id):
        """
        上传完成确认
        :param int song_id:
        :return dict:
        """
        params = {
            'songid': str(song_id),
        }
        resp = self._request_eapi('/eapi/cloud/pub/v2', b'/api/cloud/pub/v2', params)
        if resp is not None and 'code' in resp and resp['code'] == 201:
            return resp['privateCloud']
        else:
            print(resp)
        return None

    def batch(self, api_params):
        """
        批量请求api
        :param dict api_params: API列表及请求参数
            如dict(
                '/api/discovery/hotspot': json.dumps({'limit' : 12}),
                '/api/discovery/recommend/resource': json.dumps({'limit': 3}),
            )
        :return dict: 请求结果
        """
        return self._request_eapi('/eapi/batch', b'/batch', api_params)

    def set_music_u(self, music_u):
        """
        设置登录Cookie
        :param str music_u:
        """
        self._cookie['MUSIC_U'] = music_u

    def set_user_id(self, user_id):
        """
        设置当前用户ID
        :param int user_id:
        """
        self._user_id = user_id

    def _request_eapi(self, gateway_path, request_path, params, decrpyt=False):
        """
        请求eapi并获取返回结果
        :param str gateway_path: 请求网关的路径
        :param bytes request_path: 请求后端的路径
        :param dict params: 请求参数，会自动进行加密处理
        :return dict: 请求结果
        """
        params['verifyId'] = 1
        params['os'] = 'OSX'
        params['header'] = json.dumps({
            'os': 'osx',
            'appver': '1.5.9',
            'requestId': str(random.randint(10000000, 99999999)),
            'clientSign': '',
        }, separators=(',', ':'))
        params = self._eapi_encrypt(request_path, params)
        url = 'https://music.163.com' + gateway_path
        resp = self._request('POST', url, {'params': params}, encode_multipart=False)
        if resp is None:
            return None
        else:
            if decrpyt:
                data = self._eapi_decrypt(resp.data)
            else:
                data = resp.data
            return json.loads(data.decode())

    @staticmethod
    def _eapi_encrypt(path, params):
        """eapi
        接口参数加密
        :param bytes path: 请求的路径
        :param params: 请求参数
        :return str: 加密结果
        """
        params = json.dumps(params, separators=(',', ':')).encode()
        sign_src = b'nobody' + path + b'use' + params + b'md5forencrypt'
        m = hashlib.md5()
        m.update(sign_src)
        sign = m.hexdigest()
        aes_src = path + b'-36cd479b6b5-' + params + b'-36cd479b6b5-' + sign.encode()
        pad = 16 - len(aes_src) % 16
        aes_src = aes_src + bytearray([pad] * pad)
        crypt = AES.new(b'e82ckenh8dichen8', AES.MODE_ECB)
        ret = crypt.encrypt(aes_src)
        return b2a_hex(ret).upper()

    @staticmethod
    def _eapi_decrypt(data):
        """
        解密eapi返回结果
        :param bytes data: 密文
        :return bytes: 原文
        """
        crypt = AES.new(b'e82ckenh8dichen8', AES.MODE_ECB)
        data = crypt.decrypt(data)
        pad = ord(data[-1:])
        if 1 <= pad <= 16:
            data = data[:-pad]
        return data

    def _request(self, method, url, data, **urlopenkw):
        """
        发起HTTP请求
        :param string method: 请求method
        :param string url: 请求地址
        :param dict|None data: 请求的body
        :param urlopenkw: urlopen的参数
        :return bytes: 请求结果
        """
        headers = self._default_headers
        headers['Cookie'] = self._cookie.get_cookie()
        resp = self.__http_pool.request(method, url, data, headers, **urlopenkw)
        self._cookie.set_cookie(resp.headers.getlist('set-cookie'))
        if resp.status == 200:
            return resp
        else:
            return None


class Cookie:
    """
    定制的高端Cookie处理
    """

    def __init__(self, save_path='./.cookie', default_cookie=None):
        self._save_path = save_path
        try:
            with open(save_path, 'rb') as fp:
                self._cookie = pickle.load(fp)
                self._cookie = dict(default_cookie, **self._cookie)
        except (EOFError, FileNotFoundError):
            self._cookie = default_cookie and default_cookie or {}

    def __setitem__(self, key, value):
        self._cookie[key] = value

    def get_cookie(self, name=None):
        """
        获取单个cookie或所有cookie
        :param str name: Cookie名
        :return str: Cookie内容
        """
        if name is None:
            return parse.urlencode(self._cookie).replace('&', ';')
        else:
            if name in self._cookie:
                return self._cookie[name]
            else:
                return None

    def set_cookie(self, cookies):
        """
        解析header中set-cookie的内容并保存持久化
        :param tuple(str) cookies: header中set-cookie的内容
        """
        if len(cookies) == 0:
            return
        for cookie in cookies:
            cookie = cookie.split(';', 1)
            cookie = cookie[0].split('=', 1)
            if len(cookie) == 2:
                self._cookie[cookie[0]] = cookie[1]
        with open(self._save_path, 'wb') as fp:
            pickle.dump(self._cookie, fp)


def generate_device_id():
    """
    生成deviceId
    :return str:
    """
    return ('%s|%s' % (uuid.uuid1(), uuid.uuid4())).upper()
