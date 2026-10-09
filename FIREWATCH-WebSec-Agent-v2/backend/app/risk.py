SEV_WEIGHT={'critical':10.0,'high':8.0,'medium':5.0,'low':2.5,'info':0.5}
def calculate_risk(severity,confidence): return round(min(10.0,SEV_WEIGHT.get(getattr(severity,'value',str(severity)),1.0)*max(0,min(1,float(confidence)))),2)
