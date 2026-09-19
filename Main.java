import java.util.*;
public class Main{
    public static void main(String[] args){
        Scanner sc = new Scanner(System.in);
        int M = sc.nextInt();
        int samples[] = new int[M];
        for(int i =0;i<M;i++){
            samples[i] = sc.nextInt();

        }
        int N = sc.nextInt();
        for(int i =0;i<N;i++){
            int start = sc.nextInt();
            int end = sc.nextInt();
            int count = 0;
            for(int j =0;j<N;j++){
                if(samples[j]>=start && samples[j]<=end){
                    count++;
                }
            }
            System.out.println(count + " ");
        }
        sc.close();
        
    }

}
