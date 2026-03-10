package com.zoick.incidentapi.security;
/*
Threadlocal holder for the correlationId, set by CorrelationFilter at the start of every request
Read by GlobalExceptionHandler and any component that cannot access HTTPservletRequest directly
cleared by correlationfilter after the response to prevent thread pool leaks
 */
public class CorrelationContext {
    private static final ThreadLocal<String> HOLDER= new ThreadLocal<>();
    public static void set(String correlationId){
        HOLDER.set(correlationId);
    }
    public static String get(){
        String id= HOLDER.get();
        return id != null ? id : "unknown";
    }
    public static void clear(){
        HOLDER.remove();
    }
}
