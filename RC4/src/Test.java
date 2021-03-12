import java.util.Scanner;

public class Test {
    public static void main(String[] args) {
        Rc4 rc4 = new Rc4();
        Scanner in = new Scanner(System.in);
        System.out.println("请输入要加密的字符串");
        String m = in.nextLine();
        System.out.println("请输入加密的密匙");
        String key = in.nextLine();
        String c = rc4.encrypt(m, key);
        String d = rc4.encrypt(c, key);
        System.out.println("明文为：" + m + "\n密钥为：" + key + "\n密文为：" + c + "\n解密为：" + d);

    }
}
