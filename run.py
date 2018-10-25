#!/usr/bin/env python3
# -*- encoding=utf-8 -*-
import argparse
import asyncio
import cloud_music
import time


def write_log(log, front_color=None):
    """
    打日志
    :param str log:
    :param int front_color: 颜色
    """
    msg = '[%s] %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), log)
    if front_color is not None:
        msg = '\033[;%d;48m%s\033[0m' % (front_color, msg)
    print(msg)


async def upload_song(song):
    song_play = cloud_music_api.player_url((song['id'],))
    if len(song_play) == 0:
        return
    song_play = song_play[0]
    if song_play['md5'] is None or song_play['md5'] == '':
        write_log('《%s》已没有版权，无法上传咯' % song['name'], 31)
        return
    upload_check = cloud_music_api.cloud_upload_check(song_play['md5'],
                                                      song_play['size'],
                                                      song_play['br'],
                                                      song_play['type'])
    if upload_check is None:
        return
    filename = '%s - %s.%s' % (song['ar'][0]['name'], song['name'], song_play['type'])
    if upload_check['needUpload']:
        # TODO，需要上传的时候情况处理
        pass
    else:
        write_log('上传《%s》' % song['name'])
        upload_info = cloud_music_api.cloud_upload_info(song_play['md5'], upload_check['songId'], filename, song['name'],
                                                        song['name'], song_play['br'])
        if upload_info is None:
            print('%s上传失败', song['name'])
        if upload_info['exists']:
            write_log('《%s》已存在于云盘中' % song['name'], 32)
        else:
            await asyncio.sleep(upload_info['waitTime'])
            cloud_publish = cloud_music_api.cloud_publish(upload_info['songIdLong'])
            if cloud_publish is None:
                write_log('《%s》上传失败' % song['name'], 31)
            else:
                write_log('《%s》上传成功' % song['name'])


def get_song_by_play_list(play_list_id):
    """
    获取歌单内每首歌，并生成歌单上传task
    :param play_list_id:
    """
    song_list = cloud_music_api.get_all_play_list_detail(play_list_id)
    # 遍历歌单内各首歌
    for song in song_list:
        tasks.append(asyncio.ensure_future(upload_song(song)))


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser('网易云音乐网盘上传工具')
    group = arg_parser.add_argument_group('登录账号', '暂时只支持邮箱登录')
    group.add_argument('--username', '-u', help='用户名')
    group.add_argument('--password', '-p', help='密码')
    arg_parser.add_argument('--cookie', help='Cookie登录，只需要MUSIC_U')
    arg_parser.add_argument('--type', '-t', default=1, type=int, help='上传类型,1=我喜欢的音乐;2=我创建的歌单;3=所有歌单')
    arg_parser.add_argument('--bit-rate', '-br', default=320000, type=int, help='码率,128000/320000')
    args = arg_parser.parse_args()

    cloud_music_api = cloud_music.API()
    user_info = cloud_music_api.user_info()
    user_id = 0
    # 判断是否已登录过
    if user_info['code'] != 200:
        # 邮箱登录
        if args.username is not None and args.password is not None:
            cloud_music_api.login(args.username, args.password, 0)
        # Cookie登录
        elif args.cookie is not None:
            cloud_music_api.set_music_u(args.cookie)
        else:
            print('cookie登录或邮箱登录需要选择一种，更多请看-h')
            exit(1)
        user_info = cloud_music_api.user_info()
    else:
        cloud_music_api.refresh_token()
    # 获取用户ID
    if 'userPoint' in user_info and 'userId' in user_info['userPoint']:
        user_id = user_info['userPoint']['userId']
        cloud_music_api.set_user_id(user_id)
    else:
        print('登录失败')
        exit(1)

    tasks = []
    success_count = exist_count = 0
    # 获取我的歌单
    play_list = cloud_music_api.get_all_user_playlist()
    if args.type == 1:
        # 仅我喜欢的音乐
        write_log('正在获取我喜欢的音乐')
        get_song_by_play_list(play_list[0]['id'])
    elif args.type == 2:
        # 获取我创建的歌单内每首歌
        write_log('正在获取我创建的歌单')
        for play_list_item in play_list:
            if play_list_item['userId'] == user_id:
                get_song_by_play_list(play_list_item['id'])
    else:
        # 所有歌
        write_log('正在获取我收藏的所有歌单')
        for play_list_item in play_list:
            get_song_by_play_list(play_list_item['id'])

    if len(tasks) == 0:
        print('您的歌单里没有歌')
        exit(1)
    # 异步执行上传
    loop = asyncio.get_event_loop()
    loop.run_until_complete(asyncio.wait(tasks))
    loop.close()
    # 输出总结果
    write_log('上传完成，总歌曲数量%d首，成功%d，已存在%d' % (len(tasks), success_count, exist_count))
