# coding:utf-8

from flask import Blueprint
from flask import current_app
# # from ihome import db,models
import numpy
#
from detection.utils.captcha.captcha import captcha
from detection import redis_store, constants,db
from flask import current_app, jsonify, make_response, request, session,g
from detection.utils.response_code import RET
#
from detection.models import User,Rice_filed
from detection.libs.yuntongxun.sms import CCP
import random
#
import re
from sqlalchemy.exc import IntegrityError
#
# from ihome.utils.image_storage import storage
from detection.utils.commons import login_required
import MySQLdb
#
# import json

import os
from flask import Flask, render_template, request, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename
from detection import db,models

import time;

from detection.frcnn.py_faster_rcnn.tools.demo import hel

from exifread_infos import exifread_infos



# 创建蓝图对象
api = Blueprint("api_1_0", __name__)

# This is the path to the upload directory
save_path = '/home/heyue/PycharmProjects/BRP_DETECTOR/detection/static/imagedetecion/'
# These are the extension that we are accepting to be uploa
ALLOWED_EXTENSIONSS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

# For a given file, return whether it's an allowed type or not
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONSS


# 导入蓝图的视图
#from . import demo
@api.route("/")
def index():
    return "index page1"


@api.route('/upload', methods=['POST'])
@login_required
def upload():
    idd = g.user_id
    client_num=str(idd)
    ticks = time.ctime()
    uppath=save_path+client_num+'/'+ticks
    tick=ticks+'result'
    result_path=save_path+client_num+'/'+tick
    os.makedirs(uppath)
    os.makedirs(result_path)
    # Get the name of the uploaded files
    uploaded_files = request.files.getlist("file[]")
    filenames = []

    ima0name = Rice_filed.ima0name='/'+client_num+'/'+tick+'/'
    ima1name = Rice_filed.ima1name='/'+client_num+'/'+tick+'/'
    ima2name = Rice_filed.ima2name='/'+client_num+'/'+tick+'/'
    ima3name = Rice_filed.ima3name='/'+client_num+'/'+tick+'/'
    ima4name = Rice_filed.ima4name='/'+client_num+'/'+tick+'/'
    ima5name = Rice_filed.ima5name='/'+client_num+'/'+tick+'/'
    ima6name = Rice_filed.ima6name='/'+client_num+'/'+tick+'/'
    ima7name = Rice_filed.ima7name='/'+client_num+'/'+tick+'/'
    tim=Rice_filed.ticks=ticks
    

    for file in uploaded_files:
        # Check if the file is one of the allowed types/extensions
        if file and allowed_file(file.filename):
            # Make the filename safe, remove unsupported chars
            filename = secure_filename(file.filename)
            # Move the file form the temporal folder to the upload
            # folder we setup

            file.save(os.path.join(uppath, filename))

            # Save the filename into a list, we'll use it later
            filenames.append(filename)
      
            # Redirect the user to the uploaded_file route, which
            # will basicaly show on the browser the uploaded file
    # Load an html page with a link to each uploaded file
    # return render_template('/html/upload.html', filenames=filenames)
    #image detection

    raddres=uppath+'/'+filenames[0]
    

    filelen = filenames.__len__()
    for i in range(filelen):
        if i == 0:
            ima0name = ima0name+filenames[i]
        if i == 1:
            ima1name = ima1name+filenames[i]
        if i == 2:
            ima2name = ima2name + filenames[i]
        if i == 3:
            ima3name = ima3name + filenames[i]
        if i == 4:
            ima4name = ima4name+filenames[i]
        if i == 5:
            ima5name = ima5name+filenames[i]
        if i == 6:
            ima6name = ima6name + filenames[i]
        if i == 7:
            ima7name = ima7name + filenames[i]
    nums=[]
    nums=hel(uppath)
    print nums
    
    #写入数据库
    db = MySQLdb.connect("127.0.0.1", "root", "hy135391", "brp_detecton_07")

    address=Rice_filed.address
    user_id=Rice_filed.user_id
    ima0 = Rice_filed.ima0
    ima1 = Rice_filed.ima1
    ima2 = Rice_filed.ima2
    ima3 = Rice_filed.ima3
    ima4 = Rice_filed.ima4
    ima5 = Rice_filed.ima5
    ima6 = Rice_filed.ima6
    ima7 = Rice_filed.ima7
    prediction=Rice_filed.prediction
    prediction=0
    user_idd = Rice_filed.user_idd

    ans=numpy.zeros(8,int)
    for i in range(len(nums)):
        ans[i]=nums[i]

    ima0 = ans[0]
    ima1 = ans[1]
    ima2 = ans[2]
    ima3 = ans[3]
    ima4 = ans[4]
    ima5 = ans[5]
    ima6 = ans[6]
    ima7 = ans[7]

    for i in range(len(ans)):
        prediction=prediction+ans[i]

    user_id=idd
    user_idd=idd

    address=exifread_infos(raddres)

    sql = "insert into rice_filed_detection(user_id,address,ima0,ima1,ima2,ima3,ima4,ima5,ima6,ima7,prediction,user_idd,ima0name,ima1name,ima2name,ima3name,ima4name,ima5name,ima6name,ima7name,tim) " \
          "values('%d','%s','%d','%d','%d','%d','%d','%d','%d','%d','%d','%d','%s','%s','%s','%s','%s','%s','%s','%s','%s')" \
          % (user_id,address,ima0, ima1,ima2, ima3,ima4, ima5,ima6, ima7,prediction,user_idd, ima0name, ima1name, ima2name, ima3name, ima4name, ima5name, ima6name, ima7name, tim)

    cursor = db.cursor()
    try:
        cursor.execute(sql)
        db.commit()  # 提交到数据库执行，一定要记提交哦
    except Exception, e:
        db.rollback()  # 发生错误时回滚
        print e
    cursor.close()
    db.close()
    return "finish"


@api.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(uppath,filename)

@api.route("/image_codes/<image_code_id>")
def get_image_code(image_code_id):
    """
    获取图片验证码
    : params image_code_id:  图片验证码编号
    :return:  正常:验证码图片  异常：返回json
    """
    # 业务逻辑处理
    # 生成验证码图片
    # 名字，真实文本， 图片数据
    name, text, image_data = captcha.generate_captcha()

    # 将验证码真实值与编号保存到redis中, 设置有效期
    # redis：  字符串   列表  哈希   set
    # "key": xxx
    # 使用哈希维护有效期的时候只能整体设置
    # "image_codes": {"id1":"abc", "":"", "":""} 哈希  hset("image_codes", "id1", "abc")  hget("image_codes", "id1")

    # 单条维护记录，选用字符串
    # "image_code_编号1": "真实值"
    # "image_code_编号2": "真实值"

    # redis_store.set("image_code_%s" % image_code_id, text)
    # redis_store.expire("image_code_%s" % image_code_id, constants.IMAGE_CODE_REDIS_EXPIRES)
    #                   记录名字                          有效期                              记录值
    try:
        redis_store.setex("image_code_%s" % image_code_id, constants.IMAGE_CODE_REDIS_EXPIRES, text)
    except Exception as e:
        # 记录日志
        current_app.logger.error(e)
        # return jsonify(errno=RET.DBERR,  errmsg="save image code id failed")
        return jsonify(errno=RET.DBERR,  errmsg="保存图片验证码失败")

    # 返回图片
    resp = make_response(image_data)
    resp.headers["Content-Type"] = "image/jpg"
    return resp


# GET /api/v1.0/sms_codes/<mobile>?image_code=xxxx&image_code_id=xxxx
@api.route("/sms_codes/<re(r'1[34578]\d{9}'):mobile>")
def get_sms_code(mobile):
    """获取短信验证码"""
    # 获取参数
    image_code = request.args.get("image_code")
    image_code_id = request.args.get("image_code_id")

    # 校验参数
    if not all([image_code_id, image_code]):
        # 表示参数不完整
        return jsonify(errno=RET.PARAMERR, errmsg="参数不完整")

    # 业务逻辑处理
    # 从redis中取出真实的图片验证码
    try:
        real_image_code = redis_store.get("image_code_%s" % image_code_id)
    except Exception as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg="redis数据库异常")

    # 判断图片验证码是否过期
    if real_image_code is None:
        # 表示图片验证码没有或者过期
        return jsonify(errno=RET.NODATA, errmsg="图片验证码失效")

    # 删除redis中的图片验证码，防止用户使用同一个图片验证码验证多次
    try:
        redis_store.delete("image_code_%s" % image_code_id)
    except Exception as e:
        current_app.logger.error(e)

    # 与用户填写的值进行对比
    if real_image_code.lower() != image_code.lower():
        # 表示用户填写错误
        return jsonify(errno=RET.DATAERR, errmsg="图片验证码错误")

    # 判断对于这个手机号的操作，在60秒内有没有之前的记录，如果有，则认为用户操作频繁，不接受处理
    try:
        send_flag = redis_store.get("send_sms_code_%s" % mobile)
    except Exception as e:
        current_app.logger.error(e)
    else:
        if send_flag is not None:
            # 表示在60秒内之前有过发送的记录
            return jsonify(errno=RET.REQERR, errmsg="请求过于频繁，请60秒后重试")

    # 判断手机号是否存在
    try:
        user = User.query.filter_by(mobile=mobile).first()
    except Exception as e:
        current_app.logger.error(e)
    else:
        if user is not None:
            # 表示手机号已存在
            return jsonify(errno=RET.DATAEXIST, errmsg="手机号已存在")

    # 如果手机号不存在，则生成短信验证码
    sms_code = "%06d" % random.randint(0, 999999)

    # 保存真实的短信验证码
    try:
        redis_store.setex("sms_code_%s" % mobile, constants.SMS_CODE_REDIS_EXPIRES, sms_code)
        # 保存发送给这个手机号的记录，防止用户在60s内再次出发发送短信的操作
        redis_store.setex("send_sms_code_%s" % mobile, constants.SEND_SMS_CODE_INTERVAL, 1)
    except Exception as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg="保存短信验证码异常")

    # 发送短信
    try:
        ccp = CCP()
        result = ccp.send_template_sms(mobile, [sms_code, int(constants.SMS_CODE_REDIS_EXPIRES/60)], 1)
    except Exception as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.THIRDERR, errmsg="发送异常")

    # 返回值
    if result == 0:
        # 发送成功
        return jsonify(errno=RET.OK, errmsg="发送成功")
    else:
        return jsonify(errno=RET.THIRDERR, errmsg="发送失败")


@api.route("/users", methods=["POST"])
def register():

    """注册
    请求的参数： 手机号、短信验证码、密码、确认密码
    参数格式：json
    """
    # 获取请求的json数据，返回字典

    req_dict = request.get_json()
    print req_dict

    mobile = req_dict.get("mobile")
    sms_code = req_dict.get("sms_code")
    password = req_dict.get("password")
    password2 = req_dict.get("password2")

    # 校验参数
    if not all([mobile, sms_code, password, password2]):
        return jsonify(errno=RET.PARAMERR, errmsg="参数不完整")

    # 判断手机号格式
    if not re.match(r"1[34578]\d{9}", mobile):
        # 表示格式不对
        print RET.PARAMERR
        return jsonify(errno=RET.PARAMERR, errmsg="手机号格式错误")

    if password != password2:
        return jsonify(errno=RET.PARAMERR, errmsg="两次密码不一致")

    # # 从redis中取出短信验证码
    # try:
    #     real_sms_code = redis_store.get("sms_code_%s" % mobile)
    # except Exception as e:
    #     current_app.logger.error(e)
    #     return jsonify(errno=RET.DBERR, errmsg="读取真实短信验证码异常")
    #
    # # 判断短信验证码是否过期
    # if real_sms_code is None:
    #     return jsonify(errno=RET.NODATA, errmsg="短信验证码失效")
    #
    # # 删除redis中的短信验证码，防止重复使用校验
    # try:
    #     redis_store.delete("sms_code_%s" % mobile)
    # except Exception as e:
    #     current_app.logger.error(e)
    #
    # # 判断用户填写短信验证码的正确性
    # if real_sms_code != sms_code:
    #     return jsonify(errno=RET.DATAERR, errmsg="短信验证码错误")

    # 判断用户的手机号是否注册过
    # try:
    #     user = User.query.filter_by(mobile=mobile).first()
    # except Exception as e:
    #     current_app.logger.error(e)
    #     return jsonify(errno=RET.DBERR, errmsg="数据库异常")
    # else:
    #     if user is not None:
    #         # 表示手机号已存在
    #         return jsonify(errno=RET.DATAEXIST, errmsg="手机号已存在")

    # 盐值   salt

    #  注册
    #  用户1   password="123456" + "abc"   sha1   abc$hxosifodfdoshfosdhfso
    #  用户2   password="123456" + "def"   sha1   def$dfhsoicoshdoshfosidfs
    #
    # 用户登录  password ="123456"  "abc"  sha256      sha1   hxosufodsofdihsofho

    # 保存用户的注册数据到数据库中
    user = User(name=mobile, mobile=mobile)
    # user.generate_password_hash(password)



    user.password = password  # 设置属性


    try:
        print "5"
        db.session.add(user)
        db.session.commit()
    except IntegrityError as e:
        # 数据库操作错误后的回滚
        db.session.rollback()
        # 表示手机号出现了重复值，即手机号已注册过
        current_app.logger.error(e)
        return jsonify(errno=RET.DATAEXIST, errmsg="手机号已存在")
    except Exception as e:
        db.session.rollback()
        # 表示手机号出现了重复值，即手机号已注册过
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg="查询数据库异常")

    # 保存登录状态到session中
    session["name"] = mobile
    session["mobile"] = mobile
    session["user_id"] = user.id

    #创建用户文件目录
    client_num = user.id
    client_str = str(client_num)
    client_path = '/home/heyue/imagedetecion/'
    client_file = client_path + client_str
    os.makedirs(client_file)

    # 返回结果
    return jsonify(errno=RET.OK, errmsg="注册成功")


@api.route("/sessions", methods=["POST"])
def login():
    """用户登录
    参数： 手机号、密码， json
    """
    # 获取参数
    req_dict = request.get_json()
    mobile = req_dict.get("mobile")
    password = req_dict.get("password")

    print req_dict

    # 校验参数
    # 参数完整的校验
    if not all([mobile, password]):
        return jsonify(errno=RET.PARAMERR, errmsg="参数不完整")

    # 手机号的格式
    if not re.match(r"1[34578]\d{9}", mobile):
        return jsonify(errno=RET.PARAMERR, errmsg="手机号格式错误")

    # 判断错误次数是否超过限制，如果超过限制，则返回
    # redis记录： "access_nums_请求的ip": "次数"
    user_ip = request.remote_addr  # 用户的ip地址
    try:
        access_nums = redis_store.get("access_num_%s" % user_ip)
    except Exception as e:
        current_app.logger.error(e)
    else:
        if access_nums is not None and int(access_nums) >= constants.LOGIN_ERROR_MAX_TIMES:
            return jsonify(errno=RET.REQERR, errmsg="错误次数过多，请稍后重试")

    # 从数据库中根据手机号查询用户的数据对象
    try:
        user = User.query.filter_by(mobile=mobile).first()
    except Exception as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg="获取用户信息失败")

    # 用数据库的密码与用户填写的密码进行对比验证
    if user is None or not user.check_password(password):
        # 如果验证失败，记录错误次数，返回信息
        try:
            # redis的incr可以对字符串类型的数字数据进行加一操作，如果数据一开始不存在，则会初始化为1
            redis_store.incr("access_num_%s" % user_ip)
            redis_store.expire("access_num_%s" % user_ip, constants.LOGIN_ERROR_FORBID_TIME)
        except Exception as e:
            current_app.logger.error(e)

        return jsonify(errno=RET.DATAERR, errmsg="用户名或密码错误")

    # 如果验证相同成功，保存登录状态， 在session中
    session["name"] = user.name
    session["mobile"] = user.mobile
    session["user_id"] = user.id

    return jsonify(errno=RET.OK, errmsg="登录成功")


@api.route("/session", methods=["GET"])
def check_login():
    """检查登陆状态"""
    # 尝试从session中获取用户的名字
    name = session.get("name")
    # 如果session中数据name名字存在，则表示用户已登录，否则未登录
    if name is not None:
        return jsonify(errno=RET.OK, errmsg="true", data={"name": name})
    else:
        return jsonify(errno=RET.SESSIONERR, errmsg="false")


@api.route("/session", methods=["DELETE"])
def logout():
    """登出"""
    # 清除session数据
    session.clear()
    return jsonify(errno=RET.OK, errmsg="OK")

@api.route("/hh")
def test():
    uppath = '/home/heyue/imagedetecion/1/Mon Dec 31 18:56:22 2018'
    nums = []
    nums = hel(uppath)
    return "h"

@api.route("/users/auth", methods=["POST"])
@login_required
def set_user_auth():
    """保存实名认证信息"""
    user_id = g.user_id

    # 获取参数
    req_data = request.get_json()
    if not req_data:
        return jsonify(errno=RET.PARAMERR, errmsg="参数错误")

    real_name = req_data.get("real_name")  # 真实姓名
    id_card = req_data.get("id_card")  # 身份证号

    # 参数校验
    if not all([real_name, id_card]):
        return jsonify(errno=RET.PARAMERR, errmsg="参数错误")

    # 保存用户的姓名与身份证号
    try:
        User.query.filter_by(id=user_id, real_name=None, id_card=None)\
            .update({"real_name": real_name, "id_card": id_card})
        db.session.commit()
    except Exception as e:
        current_app.logger.error(e)
        db.session.rollback()
        return jsonify(errno=RET.DBERR, errmsg="保存用户实名信息失败")

    return jsonify(errno=RET.OK, errmsg="OK")

@api.route("/user/fileds", methods=["GET"])
@login_required
def get_user_filed():
    """获取房东发布的房源信息条目"""
    user_id = g.user_id
    try:
        # House.query.filter_by(user_id=user_id)
        user = User.query.get(user_id)
        fileds = user.filed
    except Exception as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg="获取数据失败")
    # 将查询到的房屋信息转换为字典存放到列表中
    fileds_list = []
    if fileds:
        for filed in fileds:
            fileds_list.append(filed.to_basic_dict())
    print fileds_list
    return jsonify(errno=RET.OK, errmsg="OK", data={"fileds": fileds_list})


@api.route("/user", methods=["GET"])
@login_required
def get_user_profile():
    """获取个人信息"""
    user_id = g.user_id
    # 查询数据库获取个人信息
    try:
        user = User.query.get(user_id)
    except Exception as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg="获取用户信息失败")

    if user is None:
        return jsonify(errno=RET.NODATA, errmsg="无效操作")

    return jsonify(errno=RET.OK, errmsg="OK", data=user.to_dict())


@api.route("/users/auth", methods=["GET"])
@login_required
def get_user_auth():
    """获取用户的实名认证信息"""
    user_id = g.user_id

    # 在数据库中查询信息
    try:
        user = User.query.get(user_id)
    except Exception as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg="获取用户实名信息失败")

    if user is None:
        return jsonify(errno=RET.NODATA, errmsg="无效操作")

    return jsonify(errno=RET.OK, errmsg="OK", data=user.auth_to_dict())



