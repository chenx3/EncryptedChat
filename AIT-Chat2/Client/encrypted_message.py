import json
import base64

class EncryptedMessage:
    @staticmethod
    def format_message(content="", purpose="0", receiver="",signature=""):
        dic = {}
        dic["content"] = base64.encodestring(content)
        dic["purpose"] = purpose
        dic["receiver"] = receiver
        dic["signature"] = signature
        return json.dumps(dic)

    @staticmethod
    def decode_message(message):
        decodejson = json.loads(message)
        decodejson["content"] = base64.decodestring(decodejson["content"])
        decodejson["signature"] = decodejson["signature"]
        return decodejson

