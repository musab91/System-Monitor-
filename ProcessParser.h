#include <algorithm>
#include <iostream>
#include <math.h>
#include <thread>
#include <chrono>
#include <iterator>
#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <time.h>
#include <unistd.h>
#include "constants.h"


using namespace std;

class ProcessParser{
private:
    std::ifstream stream;
    public:
    static string getCmd(string pid); 
    static vector<string> getPidList();
    static std::string getVmSize(string pid); 
    static std::string getCpuPercent(string pid);
    static long int getSysUpTime(); 
    static std::string getProcUpTime(string pid); 
    static string getProcUser(string pid); 
    static vector<string> getSysCpuPercent(string coreNumber = ""); 
    static float getSysRamPercent(); 
    static string getSysKernelVersion(); 
    static int getTotalThreads(); 
    static int getTotalNumberOfProcesses(); 
    static int getNumberOfRunningProcesses(); 
    static string getOSName(); 
    static std::string PrintCpuStats(std::vector<std::string> values1, std::vector<std::string>values2); 
    static bool isPidExisting(string pid); 
};

 string ProcessParser::getCmd(string pid){
   std::ifstream myStream;
   Util::getStream(Path::basePath() + pid + Path::cmdPath(), myStream);
   std::string cmd;
   getline(myStream,cmd);
   return cmd; 
}

string ProcessParser::getVmSize(string pid){
  string line;
  string key = "VmData";
  string value;
  float result;
  
  ifstream myStream;
  Util::getStream(Path::basePath() + pid + Path::statusPath(), myStream);
  
  while(getline(myStream, line)){
    if(line.compare(0,key.size(), key) == 0){
      std::istringstream buf(line);
      string x;
      buf >> x >> result;
      result /= 1000;
    }
  }
  return to_string(result);
}

std::string ProcessParser::getCpuPercent(string pid){
  ifstream myStream;
  string line;
  Util::getStream(Path::basePath() + pid + "/" + Path::statPath(),myStream);

  float utime = stof(ProcessParser::getProcUpTime(pid));
  getline(myStream, line);
  
  istringstream buf(line);
  istream_iterator<string> beg(buf), end;
  std::vector<string> values(beg,end);

  float stime = stof(values[14]);
  float cutime = stof(values[15]);
  float cstime = stof(values[16]);
  float starttime = stof(values[21]);

  float uptime = ProcessParser::getSysUpTime();
  float freq = sysconf(_SC_CLK_TCK);

  float totalTime = utime + stime + cutime + cstime + starttime;
  float seconds = uptime - (starttime/freq);
  float result = 100.0*((totalTime/freq)/seconds);

  return to_string(result);
}

std::string ProcessParser::getProcUpTime(string pid){
  ifstream myStream;
  string line;
  Util::getStream(Path::basePath() + pid + "/" + Path::statPath(),myStream);
  getline(myStream, line);
  
  istringstream buf(line);
  istream_iterator<string> beg(buf), end;
  std::vector<string> values(beg,end);

  return to_string(float(stof(values[13])/sysconf(_SC_CLK_TCK)));
}

long int ProcessParser::getSysUpTime(){
    string line;
    ifstream myStream;
    Util::getStream((Path::basePath() + Path::upTimePath()), myStream);
    getline(myStream,line);
    istringstream buf(line);
    istream_iterator<string> beg(buf), end;
    vector<string> values(beg, end);
    return stoi(values[0]);
}


string ProcessParser::getProcUser(string pid){
  ifstream stream;
  string line;
  string key = "Uid";
  string userID;
  string result;
  Util::getStream(Path::basePath() + pid + Path::statusPath(), stream);
  while(getline(stream, line)){
    if(line.compare(0,key.size(), key) == 0){
      istringstream buf(line);
      istream_iterator<string> beg(buf), end;
      vector<string> values(beg,end);
      userID = values[1];
      break;
    }
  }
  stream.close();
  Util::getStream("/etc/passwd", stream);
  size_t found;
  while(getline(stream, line)){
    found = line.find("x:"+userID);
    if(found != string::npos){
      result = line.substr(0, found-1);
      return result;
    }
  }
  return "";
}

vector<string> ProcessParser::getPidList(){
    DIR* dir;
    vector<string> container;
    if(!(dir = opendir("/proc")))
        throw std::runtime_error(std::strerror(errno));

    while (dirent* dirp = readdir(dir)) {
        if(dirp->d_type != DT_DIR)
            continue;
        if (all_of(dirp->d_name, dirp->d_name + std::strlen(dirp->d_name), [](char c){ return std::isdigit(c); })) {
            container.push_back(dirp->d_name);
        }
    }
    if(closedir(dir))
        throw std::runtime_error(std::strerror(errno));
    return container;
}

int getNumberOfCores()
{
    // Get the number of host cpu cores
    string line;
    string name = "cpu cores";
    ifstream stream;
  	Util::getStream((Path::basePath() + "cpuinfo"),stream);
    while (std::getline(stream, line)) {
        if (line.compare(0, name.size(),name) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            return stoi(values[3]);
        }
    }
    return 0;
}

float getSysActiveCpuTime(vector<string> values)
{
    return (stof(values[S_USER]) +
            stof(values[S_NICE]) +
            stof(values[S_SYSTEM]) +
            stof(values[S_IRQ]) +
            stof(values[S_SOFTIRQ]) +
            stof(values[S_STEAL]) +
            stof(values[S_GUEST]) +
            stof(values[S_GUEST_NICE]));
}

float getSysIdleCpuTime(vector<string>values)
{
    return (stof(values[S_IDLE]) + stof(values[S_IOWAIT]));
}
bool ProcessParser::isPidExisting(string pid){
  vector<string> list = ProcessParser::getPidList();
  for(auto& p: list){
    if(p.compare(pid) == 0)
      return true;
  } 
    return false;
}


vector<string> ProcessParser::getSysCpuPercent(string coreNumber)
{
    string line;
    string name = "cpu" + coreNumber;
    string value;
    int result;
    ifstream stream;
  	Util::getStream(Path::basePath() + Path::statPath(), stream);
    while (std::getline(stream, line)) {
        if (line.compare(0, name.size(),name) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            return values;
        }
    }
    return (vector<string>());
}

string ProcessParser::PrintCpuStats(vector<string> values1, vector<string> values2)
{

    float activeTime = getSysActiveCpuTime(values2)-getSysActiveCpuTime(values1);
    float idleTime = getSysIdleCpuTime(values2) - getSysIdleCpuTime(values1);
    float totalTime = activeTime + idleTime;
    float result = 100.0*(activeTime / totalTime);
    return to_string(result);
}


float ProcessParser::getSysRamPercent()
{
    string line;
    string name1 = "MemAvailable:";
    string name2 = "MemFree:";
    string name3 = "Buffers:";

    string value;
    int result;
    ifstream stream;
  	Util::getStream((Path::basePath() + Path::memInfoPath()),stream);
    float totalMem = 0;
    float freeMem = 0;
    float buffers = 0;
    while (std::getline(stream, line)) {
        if (totalMem != 0 && freeMem != 0)
            break;
        if (line.compare(0, name1.size(), name1) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            totalMem = stof(values[1]);
        }
        if (line.compare(0, name2.size(), name2) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            freeMem = stof(values[1]);
        }
        if (line.compare(0, name3.size(), name3) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            buffers = stof(values[1]);
        }
    }

    return float(100.0*(1-(freeMem/(totalMem-buffers))));
}

string ProcessParser::getSysKernelVersion()
{
    string line;
    string name = "Linux version ";
    ifstream stream;
  	Util::getStream((Path::basePath() + Path::versionPath()), stream);
    while (std::getline(stream, line)) {
        if (line.compare(0, name.size(),name) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            return values[2];
        }
    }
    return "";
}

string ProcessParser::getOSName(){
    string line;
    string name = "PRETTY_NAME=";

    ifstream stream; 
  	Util::getStream(("/etc/os-release"), stream);

    while (std::getline(stream, line)) {
        if (line.compare(0, name.size(), name) == 0) {
              std::size_t found = line.find("=");
              found++;
              string result = line.substr(found);
              result.erase(std::remove(result.begin(), result.end(), '"'), result.end());
              return result;
        }
    }
    return "";

}

int ProcessParser::getTotalThreads(){
    string line;
    int result = 0;
    string name = "Threads:";
    vector<string>_list = ProcessParser::getPidList();
  	ifstream stream;
    for (int i=0 ; i<_list.size();i++) {
      string pid = _list[i];
      Util::getStream((Path::basePath() + pid + Path::statusPath()), stream);
      while (std::getline(stream, line)) {
        if (line.compare(0, name.size(), name) == 0) {
          istringstream buf(line);
          istream_iterator<string> beg(buf), end;
          vector<string> values(beg, end);
          result += stoi(values[1]);
          break;
        }
      }
      stream.close();
    }
    return result;
}


int ProcessParser::getTotalNumberOfProcesses()
{
    string line;
    int result = 0;
    string name = "processes";
    ifstream stream;
  	Util::getStream((Path::basePath() + Path::statPath()), stream);
    while (std::getline(stream, line)) {
        if (line.compare(0, name.size(), name) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            result += stoi(values[1]);
            break;
        }
    }
    return result;
}

int ProcessParser::getNumberOfRunningProcesses()
{
    string line;
    int result = 0;
    string name = "procs_running";
    ifstream stream;
  	Util::getStream((Path::basePath() + Path::statPath()), stream);
    while (std::getline(stream, line)) {
        if (line.compare(0, name.size(), name) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            result += stoi(values[1]);
            break;
        }
    }
    return result;
}