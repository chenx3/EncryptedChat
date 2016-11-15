class EncryptedMessage:
    @staticmethod
    def format_message(content="", purpose="0"):
        return content + purpose

    @staticmethod
    def decode_message(message):
        dic = {"content": message[:len(message) - 1], "purpose": message[-1]}
        print("content: "+ dic["content"])
        print("purpose: " + dic["purpose"])
        return dic
