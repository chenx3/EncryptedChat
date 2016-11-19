import json
import base64

class EncryptedMessage:
    @staticmethod
    def format_message(content="", purpose="0", receiver="",signature="",sequence_number = 0):
        dic = {}
        dic["content"] = base64.encodestring(content)
        dic["purpose"] = purpose
        dic["receiver"] = receiver
        dic["signature"] = signature
        dic["sequence_number"] = sequence_number
        return json.dumps(dic)

    @staticmethod
    def decode_message(message):
        decodejson = json.loads(message)
        decodejson["content"] = base64.decodestring(decodejson["content"])
        return decodejson

