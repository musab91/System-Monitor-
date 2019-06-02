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
    static string getCmd(string pid); //Done
    static vector<string> getPidList(); //Done
    static std::string getVmSize(string pid); //Done
    static std::string getCpuPercent(string pid); //Done
    static long int getSysUpTime(); //Done
    static std::string getProcUpTime(string pid); //Done
    static string getProcUser(string pid); //Done
    static vector<string> getSysCpuPercent(string coreNumber = ""); //Done
    static float getSysRamPercent(); //Done
    static string getSysKernelVersion(); //Done
    static int getTotalThreads(); //Done
    static int getTotalNumberOfProcesses(); //Done
    static int getNumberOfRunningProcesses(); //Done
    static string getOSName(); //Dome
    static std::string PrintCpuStats(std::vector<std::string> values1, std::vector<std::string>values2); //Done
    static bool isPidExisting(string pid); //Done
};

// TODO: Define all of the above functions below:
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

  float total_time = utime + stime + cutime + cstime + starttime;
  float seconds = uptime - (starttime/freq);
  float result = 100.0*((total_time/freq)/seconds);

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
      //cout<<"The user ID is "<<userID<<endl;
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
    // Basically, we are scanning /proc dir for all directories with numbers as their names
    // If we get valid check we store dir names in vector as list of machine pids
    vector<string> container;
    if(!(dir = opendir("/proc")))
        throw std::runtime_error(std::strerror(errno));

    while (dirent* dirp = readdir(dir)) {
        // is this a directory?
        if(dirp->d_type != DT_DIR)
            continue;
        // Is every character of the name a digit?
        if (all_of(dirp->d_name, dirp->d_name + std::strlen(dirp->d_name), [](char c){ return std::isdigit(c); })) {
            container.push_back(dirp->d_name);
        }
    }
    //Validating process of directory closing
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
    // It is possible to use this method for selection of data for overall cpu or every core.
    // when nothing is passed "cpu" line is read
    // when, for example "0" is passed  -> "cpu0" -> data for first core is read
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
            // set of cpu data active and idle times;
            return values;
        }
    }
    return (vector<string>());
}

string ProcessParser::PrintCpuStats(vector<string> values1, vector<string> values2)
{

    float active_time = getSysActiveCpuTime(values2)-getSysActiveCpuTime(values1);
    float idle_time = getSysIdleCpuTime(values2) - getSysIdleCpuTime(values1);
    float total_time = active_time + idle_time;
    float result = 100.0*(active_time / total_time);
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
    float total_mem = 0;
    float free_mem = 0;
    float buffers = 0;
    while (std::getline(stream, line)) {
        if (total_mem != 0 && free_mem != 0)
            break;
        if (line.compare(0, name1.size(), name1) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            total_mem = stof(values[1]);
        }
        if (line.compare(0, name2.size(), name2) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            free_mem = stof(values[1]);
        }
        if (line.compare(0, name3.size(), name3) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            buffers = stof(values[1]);
        }
    }
    //calculating usage:
    return float(100.0*(1-(free_mem/(total_mem-buffers))));
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
      //getting every process and reading their number of their threads
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