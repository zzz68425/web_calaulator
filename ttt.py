#建立物件並測試self

class Config:
    default_timeout = 10

    def __init__(self, timeout=None, name="default"):
        self.timeout = timeout or type(self).default_timeout
        self.name = name

    # 一般「實例方法」：第一參數是 self（需要先有物件）
    def set_timeout(self, t):
        self.timeout = t
        return self  # 回傳同一個實例
if __name__ == "__main__":
    obj = Config()
    print(obj.set_timeout(20).name)
