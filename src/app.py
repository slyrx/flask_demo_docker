from flask import Flask
from flask import request
from flask import jsonify
import datetime
import utils
import hit
from WXBizMsgCrypt3 import WXBizMsgCrypt
import xml.etree.cElementTree as ET

startTime = datetime.datetime.now().strftime("%Y-%b-%d %H:%M:%S")

app = Flask(__name__)

@app.route("/")
def show_details() :
    global startTime
    #temp = request.args.get('msg_signature')

    return "<html>" + \
           "<head><title>Docker + Flask Demo</title></head>" + \
           "<body>" + \
           "<table>" + \
           "<tr><td> Start Time </td> <td>" +  startTime + "</td> </tr>" \
           "<tr><td> Hostname </td> <td>" + utils.gethostname() + "</td> </tr>" \
           "<tr><td> Local Address </td> <td>" + utils.getlocaladdress() + "</td> </tr>" \
           "<tr><td> Remote Address </td> <td>" + request.remote_addr + "</td> </tr>" \
           "<tr><td> Server Hit </td> <td>" + str(hit.getServerHitCount()) + "</td> </tr>" \
           "</table>" + \
           "</body>" + \
           "</html>"

@app.route("/test", methods=['GET', 'POST'])
def show_post():
    sToken = "4MClQBu"
    sEncodingAESKey = "aeySssBohM4e1cPLZFyUCUX4lVan1kfBbSNQeSLgEoI"
    sCorpID = "wwac92dd00a6ef82d7"

    wxcpt = WXBizMsgCrypt(sToken, sEncodingAESKey, sCorpID)
    print("level 1")
    sVerifyMsgSig = request.args.get('msg_signature')
    sVerifyTimeStamp = request.args.get('timestamp')
    sVerifyNonce = request.args.get('nonce')
    sVerifyEchoStr = request.args.get('echostr')
    print("level 2")
    ret, sEchoStr = wxcpt.VerifyURL(sVerifyMsgSig, sVerifyTimeStamp, sVerifyNonce, sVerifyEchoStr)
    print("level 3", sEchoStr)
    if (ret != 0):
        print("ERR: VerifyURL ret: " + str(ret))

    sReqMsgSig = "0c3914025cb4b4d68103f6bfc8db550f79dcf48e"
    sReqTimeStamp = "1476422779"
    sReqNonce = "1597212914"
    sReqData = "<xml><ToUserName><![CDATA[ww1436e0e65a779aee]]></ToUserName>\n<Encrypt><![CDATA[Kl7kjoSf6DMD1zh7rtrHjFaDapSCkaOnwu3bqLc5tAybhhMl9pFeK8NslNPVdMwmBQTNoW4mY7AIjeLvEl3NyeTkAgGzBhzTtRLNshw2AEew+kkYcD+Fq72Kt00fT0WnN87hGrW8SqGc+NcT3mu87Ha3dz1pSDi6GaUA6A0sqfde0VJPQbZ9U+3JWcoD4Z5jaU0y9GSh010wsHF8KZD24YhmZH4ch4Ka7ilEbjbfvhKkNL65HHL0J6EYJIZUC2pFrdkJ7MhmEbU2qARR4iQHE7wy24qy0cRX3Mfp6iELcDNfSsPGjUQVDGxQDCWjayJOpcwocugux082f49HKYg84EpHSGXAyh+/oxwaWbvL6aSDPOYuPDGOCI8jmnKiypE+]]></Encrypt>\n<AgentID><![CDATA[1000002]]></AgentID>\n</xml>"
    ret, sMsg = wxcpt.DecryptMsg(sReqData, sReqMsgSig, sReqTimeStamp, sReqNonce)
    print(ret, sMsg)
    if (ret != 0):
        print("ERR: DecryptMsg ret: " + str(ret))

    if sMsg:
        xml_tree = ET.fromstring(sMsg)
        content = xml_tree.find("Content").text
        print(content)
    else:
        content = "bad msg!"


    return sEchoStr

@app.route("/json")
def send_json() :
    global startTime
    return jsonify( {'StartTime' : startTime,
                     'Hostname': utils.gethostname(),
                     'LocalAddress': utils.getlocaladdress(),
                     'RemoteAddress':  request.remote_addr,
                     'Server Hit': str(hit.getServerHitCount())} )

if __name__ == "__main__":
    app.run(debug = True, host = '0.0.0.0')
