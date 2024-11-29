package util;

public enum CertType {
    MALE,
    FEMALE,
    COLLEGE_GRADUATE,
    AGE_IN_TWENTIES,
    AGE_IN_THIRTIES,
    AGE_IN_FOURTIES,
    SMOKER,
    PET_LOVER,
    HATES_SAND;
    
    public static CertType typeFromString(String type){
        switch(type.toLowerCase()){
            case "male": return MALE;
            case "female": return FEMALE;
            case "college_graduate": return COLLEGE_GRADUATE;
            case "age_in_twenties": return AGE_IN_TWENTIES;
            case "age_in_thirties": return AGE_IN_THIRTIES;
            case "age_in_fourties": return AGE_IN_FOURTIES;
            case "smoker": return SMOKER;
            case "pet_lover": return PET_LOVER;
            case "hates_sand": return HATES_SAND;
            default: return null;
        }
    }
}


