package org.zenis.BurpScaffold.Utils;


import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

public class AlgUtils {

//    https://blog.csdn.net/m0_66782750/article/details/123980925
    /**
     * 差集(基于API解法) 适用于小数据量
     * 求List1中有的但是List2中没有的元素
     * 时间复杂度 O(list1.size() * list2.size())
     */
    public static List<String> subList(List<String> list1, List<String> list2) {
        list1.removeAll(list2);
        return list1;
    }

    /**
     * 差集(基于常规解法）优化解法1 适用于中等数据量
     * 求List1中有的但是List2中没有的元素
     * 空间换时间降低时间复杂度
     * 时间复杂度O(Max(list1.size(),list2.size()))
     */
    public static List<String> subList1(List<String> list1, List<String> list2) {
        //空间换时间 降低时间复杂度
        Map<String, String> tempMap = new HashMap<>();
        for(String str:list2){
            tempMap.put(str,str);
        }
        //LinkedList 频繁添加删除 也可以ArrayList容量初始化为List1.size(),防止数据量过大时频繁扩容以及数组复制
        List<String> resList = new LinkedList<>();
        for(String str:list1){
            if(!tempMap.containsKey(str)){
                resList.add(str);
            }
        }
        return resList;
    }

    /**
     * 差集(基于java8新特性)优化解法2 适用于大数据量
     * 求List1中有的但是List2中没有的元素
     */
    public static List<String> subList2(List<String> list1, List<String> list2) {
        Map<String, String> tempMap = list2.parallelStream().collect(Collectors.toMap(Function.identity(), Function.identity(), (oldData, newData) -> newData));
        return list1.parallelStream().filter(str-> !tempMap.containsKey(str)).collect(Collectors.toList());
    }

    public static List<Integer> subList2Integer(List<Integer> list1, List<Integer> list2) {
        Map<Integer, Integer> tempMap = list2.parallelStream().collect(Collectors.toMap(Function.identity(), Function.identity(), (oldData, newData) -> newData));
        return list1.parallelStream().filter(id-> !tempMap.containsKey(id)).collect(Collectors.toList());
    }
}
