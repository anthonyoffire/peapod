package util;
/**
 * Available group logic operations for PEAPOD
 */
public enum LogicOpType {
    XOR,
    ANDNAND,
    OR,
    XOFN,
    NA;

    public static LogicOpType typeFromString(String type){
        switch(type){
            case "XOR": return XOR;
            case "ANDNAND": return ANDNAND;
            case "OR": return OR;
            case "XOFN": return XOFN;
            case "NA": return NA;
            default: return null;
        }
    }
}