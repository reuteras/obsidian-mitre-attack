It is assumed that [[APT28]] hacked the company via a [[Spearphishing Link - T1598.003|Spearphishing Link]] to the malware [[ADVSTORESHELL]] hosted on a [[Virtual Private Server - T1583.003|virtual private server]] to gain access and run a [[Tool - T1588.002|tool]] which in this case was [[Mimikatz]]. After that [[APT28]] used [[Elevated Execution with Prompt - T1548.004|Elevated Execution with Prompt]] and exfiltrated [[Data from Local System - T1005]]. 

## Techniques
```dataview
list from #technique 
WHERE contains(file.inlinks, this.file.link)
```

## Tools and malware
```dataview
list from #tool or #malware  
WHERE contains(file.inlinks, this.file.link)
```
