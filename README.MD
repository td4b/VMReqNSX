# VMResNSX Readme
**General Information**

*This is a small program written to find all virtual machines and their IP addresses associated with a security group in vmware NSX.*
*In order to run the script simply update the .yaml file with the appropriate NSX Manager API interface as well as the username and password.*
*The program will prompt the user for the name of the security group, and then return a list of virtual machines and their corresponding IP addresses.*
*If virtual machines do not exist in the security group an error will be thrown.*

**Required Software**

* Python 3.4+
  * yaml
  * xml.etree
  * sockets
  * requ