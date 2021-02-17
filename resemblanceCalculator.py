class ResemblanceCalculator():
    @classmethod
    def get_shingle(cls, word, size):
        # size는 슬라이스할 길이
        shingle = set()
        for i in range(len(word) - size):
            shingle.add(word[i: i + size])
        return shingle

    @classmethod
    def get_resemblance(cls, word1, word2, size):
        word1 = word1.lower() 
        word2 = word2.lower()

        s1 = cls.get_shingle(word1, size)
        s2 = cls.get_shingle(word2, size)

        if(len(s1) == 0 or len(s2) == 0):
            return False

        intersection = s1 & s2
        union = s1 | s2

        intersection_size = len(intersection)
        union_size = len(union)

        resemblance = intersection_size / union_size # 두 set의 유사도
        c1 = intersection_size / len(s1) # containment : s1에 s1과 s2의 교집합이 얼마나 포함되어있는가
        c2 = intersection_size / len(s2)

        print(resemblance, c1, c2)
        if resemblance > 0.6:
            return True

        return False
