public class Rc4 {
    public String encrypt(String m, String key) {
        Integer[] S = new Integer[256];//S盒
        Character[] keySchaedul = new Character[m.length()];//生成的密钥流
        StringBuffer cipherText = new StringBuffer();
        ksa(S, key);
        rpga(S, keySchaedul, m.length());
        for (int i = 0; i < m.length(); ++i) {
            cipherText.append((char) (m.charAt(i) ^ keySchaedul[i]));
        }
        return cipherText.toString();
    }

    //KSA密钥调度算法
    /*
     *通过key对S盒进行一个置换，也就是对S盒进行一个重新排列
     */
    public void ksa(Integer[] s, String key) {
        for (int i = 0; i < 256; ++i) {
            s[i] = i;
        }
        int j = 0;
        for (int i = 0; i < 256; ++i) {
            j = (j + s[i] + key.charAt(i % key.length())) % 256;
            swap(s, i, j);
        }
    }

    /*
     *RGPA伪随机生成算法
     * 利用通过KSA重新排列的S盒来产生任意长度的密钥流
     */
    public void rpga(Integer[] s, Character[] keySchedul, int mLength) {
        int i = 0, j = 0;
        for (int k = 0; k < mLength; ++k) {
            i = (i + 1) % 256;
            j = (j + s[i]) % 256;
            swap(s, i, j);
            keySchedul[k] = (char) (s[(s[i] + s[j]) % 256]).intValue();
        }
    }

    public void swap(Integer[] s, int i, int j) {
        Integer temp = s[i];
        s[i] = s[j];
        s[j] = temp;
    }
}
