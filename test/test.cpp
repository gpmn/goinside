#include <stdio.h>
#include <string>
#include <iostream>
#include "libgoinside.h"

using namespace std;

int main(int argc, const char* argv[]){
     string tmp;
     tmp = string(argv[0]) + " fffffffff\n";
     cout << tmp << endl;
     ParseEmbedded();
     return 0;
}
