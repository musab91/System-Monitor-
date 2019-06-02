#include <iostream>
#include "util.h"
//#include "constants.h"
#include <typeinfo>
#include "ProcessParser.h"


int main(){
  
  //Testing the getCmd in process parser 
  std::cout<<"path to be tested: /proc/434/cmdline \n";
  std::string pid = "443";
  std::cout << ProcessParser::getCmd(pid) << std::endl;
  
  //Testing getVmSize from process parser
  std::string vmSize = ProcessParser::getVmSize(pid);
  std::cout<<vmSize<<std::endl;
  std::cout<<ProcessParser::getCpuPercent(pid)<<std::endl;
  std::cout<<"uid is "<<ProcessParser::getProcUser(pid)<<std::endl;
  std::vector<string> pids = ProcessParser::getPidList();
  for(auto & i: pids){
    std::cout<<i<<"\n";
  }
  std::cout<<"----------------\n";
  std::cout << ProcessParser::isPidExisting("76") << "\n";
  vector<string> v;
  v = ProcessParser::getSysCpuPercent("1");
  for(auto & i: v){
    std::cout<<i<<"\n";
  }
   std::cout<<"----------------\n";
  std::cout<<get_sys_active_cpu_time(v)<<std::endl;
}