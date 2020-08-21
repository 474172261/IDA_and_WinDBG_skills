# what is this?
This project contains scripts and skills about IDA and windbg during my research.

# details
**fix_jumpout.py** is an IDA script to fix jumpout in a symbol function in a binary database with function symbols.
```Example: function good_test, sub_112333
before:
void good_test(void){
 jmpout sub_112333;
}

void sub_112333(void){
 ret;
}

after:
void good_test(void){
 ret;
}
```
