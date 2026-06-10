
# File Content Check    

This Check Monitors the Content of a File, and reacts on them.


After installation of the MKP - you find a new Agent Rule at Setup -> Agents -> Windows, Linux, Solaris, AIX -> File Content Check:


![App Screenshot](https://cf.eude.rocks/pictus/1.png)

Click on Add Rule, define your conditions and click then on Add new Entry

![App Screenshot](https://cf.eude.rocks/pictus/3.png)

Service Name Prefix - defines the Prefix for the Service
Service Name - The actual Name you want
File Path - The Path including the file you want to parse
State if no rule matches - defines the State if no Searched String is found
Status Matching Rules - here you define what content you look for 

Conditions to choose from which are self explanatory, as:
Text contains,  Text equals, Regular Expression, Text Starts with, Text Ends with, Numeric less than, Numeric less than or equal, Numeric greater than, Numeric greater than or equal, Numeric range inclusive, Outside Numeric Range.

All Numeric Values include Metrics.

