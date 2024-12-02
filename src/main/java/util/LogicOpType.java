package util;
/**
 * Available group logic operations for PEAPOD
 */
public enum LogicOpType {
    XOR,
    ANDNAND,
    OR,
    XOFN,
    NA,
    NOT;

    public static LogicOpType typeFromString(String type){
        switch(type){
            case "XOR": return XOR;
            case "ANDNAND": return ANDNAND;
            case "OR": return OR;
            case "XOFN": return XOFN;
            case "NA": return NA;
            case "NOT": return NOT;
            default: return null;
        }
    }
}