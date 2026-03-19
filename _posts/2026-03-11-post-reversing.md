---
title: "리버싱 및 악성코드 분석 개념 및 상세 내용"
categories:
  - 리버싱
tags:
  - 리버싱
---

REV031182152

------------------------------------------------------------------------------------
과정명: 침해사고 대응 훈련
과목명: 리버스 코드 엔지니어링 훈련
강사명: 최진솔
노트: 브라우저 -> http://10.10.1.101/
------------------------------------------------------------------------------------

A.c     ->      A.obj     ->   a.exe
    (컴파일)             (링킹)

컴파일 : 기계어로 변환

링커 시 (기계어로 변환됐지만 메모리 로드x , 메모리주소 부여과정)
1.메모리어디에
2.어디서부터시작
3.외부라이브러리 어떤 함수(예를들어 printf함수, windows에서 .dll파일들)


PE파일 구조 (Windows)
+---------------------+
| DOS Header          |  -> 시그니처(ex. 4D 5A/ MZ시그니처),e_lfanew(ex. 0x3C필드 고정) -여기서부터ER시작지점(NT_HEAder)
+---------------------+
| DOS Stub            |  
+---------------------+
| NT Header(3가지구성요소)|
| - PE Signature      |
+---------------------+
| - COFF File Header  | ->Number of section(세션개수)
+---------------------+
| - Optional Header   |  -> Imagge Base(I.B)(1.메모리어디에) / Address of Entry Point(AoP) (2.어디서부터시작)
+---------------------+
| Section Table       |
+---------------------+
| Section 1 (.text)   | ->기계어코드  / R_X
| Section 2 (.data)   | ->전역변수 정의  / RW_
| Section 3 (.rdata)  |
| Section 4 (.rsrc)   | -아이콘,동영상,리소스 / R__
| Section 5 (.reloc)  |
| Section 6 (.idata)  | ->import address table(3.외부라이브러리 어떤 함수 위치가있다->바인딩과정(셸코드들은 셀프바인딩해야함/ 이작업은 로더가해줌) / RW_
+---------------------+

OPTIONAL_HEADER -> Imagge Base(I.B)(1.메모리어디에)
                -> Address of Entry Point(AoP) (2.어디서부터시작)
ex)
I.B=0x400000
AoP=0x1B90
offse?(0x1B90건너띄고부터 시작)


32비트만지원 ->PEview
64비트 ->CFF EXploreer (값을 변경해서 저장도할수있음


1.Section Headers  -> virtual Address(실제데이터의크기), Rawsize, raw address characteristics(속성값)
cf)섹션을나누는이유는 섹션마다 실행권한이 다르므로 보안상

2.idata) 
PFile
RVA- >메모리에올렸을때 주소값 (.idata주소+RVA주소)


3.IAT Tables (함수인데 어디속하는거지)/ *정말중요 ->백신프로그램 대게 이부분을봄 (악성프로그램들은 권한상승이나디버깅등등 API들을사용하기에)
API hashing -> 요즘은그래서 해시값으로 해서 악성프로그램. 특히 셸코드


--------------------
가상메모리공간에 대한 개념
0에서 FFFFf까지
실제메모리는 예ㅖ를들어 0x10 0x20인데 가상메모리ㅗ에서 0에서 FFFFf까지 실행파일들이 착각
단편화(실제메모리에서 중간중간남는) 이 발생하기에 가상메모리의 등장 ->mapping table도 등장 단편화된곳부분들 쪼개서 사용
그러므로 B.exe는 a.exe의 실제 주소를 절대 알수없게됨

페이징이란?


x.dbg32 -> 실제동적 (프로그램실행됨)
IDA, Ghidre -> 정적

x.dbg32 (calc.exe 2개 비교)

f8->디버깅한줄실ㄹ행
f9 ->breakpoint까지간다
ctrl + g ->이동
; -> 라벨단축키 (thread)
- ->이전으로
shift + + ->앞으로

상단Memory Map -> 가상공간주소임을 알수있음\
-> 그후 IDA에서 메인함수주소찾아서 x32로 접근했음 (실행파일이면 다를지언정 함수다보니 주소동일하니)

+import table메모리에 어케올라갔는지
peview에서  import directory tavle에서 import Name table RVA, Name RVA,import Address Table RVA 부분에 dll들 바인딩하면서 Address table에 적혀지는구조

우클릭> Hex > AscII

상단전화기같은부분 -> 관리하느놈듈


--------------
메모리에서 값을 CPU로 버스를통해가져오고 실제연산은 cpu에서 진행하는데 산술논리연산을 하기위한 cpu에서 임시저장공간 ->레지스터(cpu 내부에있는 빠르게쓰기위한 메모장공간/ 물리적으로 메모리랑 cpu거리는 멀기에)

EAX -> 산술연산 , 값 저장 (결과값을 반환할때)
ECX -> 카운터 레지스터(loop문)
EDX ->
EBP(스택의바닥), ESP -> 스택프레임(SP)조정 
ESI,EDI 
EIP -> 다음에 실행할 주소를 가리키고있음(엔트리포인트)
플래그레지스터 ->ZF만


우클릭 > Set EIP Here(EIP는무조건적으로 가리키고있어야함)

어셈블리어
MOV [1번파라미터] [2번파라미터] ->2번파라미터를 1번파라미터에
AND 뺴기인데 비트연산
SUB 빼기


Q1)
InserMe라는 파일을 PE_section실행파일에 섹션으로 추가
섹션명은 .extra

ㄴoptional header -> sizeOfImage(프로그램이 메모리에 로드될 때 차지하는 전체 메모리 크기) 7000에서 8000으로바꿔줘야함이것도


--------
03.12.목요일


sample.c에대한 코드 -> 실행파일(exe)해서 소스코드 분석해봄

ex) sample.c -> .exe컴파일해서 x342dbg 


#include <stdio.h>

int loop_count = 0;
int sum(int a, int b) {
    return a + b;
}

int loop() {
    int result = 0;
    loop_count = 10;
    for(int i = 0; i < loop_count; ++i) {
        result = result + i;
    }
    return result;
}

int main(int argc, char *argv[]) {
    int var_a = 5;
    int var_b = 7;

    printf("%d + %d = %d\n", var_a, var_b, sum(var_a, var_b));
    printf("loop() function's return value : %d", loop());
}



*스택프레임구조 (함수)

push ebp
mov ebp,esp
and esp,FFFFFF0
sub esp,20 

ex) main함수에 call A 로 A함수를 불러오면서 실제 메모리 스택프레임의 예시

<Low Address>
+------------------+  
| func(B)          |   
+------------------+  
| func(A).EBP      |  
+------------------+  
| func(A)의 SFP    |  
+------------------+
| func(A)          |  -> 만약 func(A)안에 func(B)가 있을경우 
|                  |
+------------------+  -> EBP,ESP  / mov ebp,esp 명령어 할떄
| main()의 EBP     |  ->
+------------------+
| Main()의 SFP      |  -> 이전 함수의 스택 프레임 기준점(EBP)을 저장(전 함수의 밑부분) / push ebp할때 레지스터값에 저장이되면서
+------------------+
| Return Addres    |   -> call실행할때 메모리값에 예를들어 call끝나고 다음실행할 주소를 저장하고 func(A)로 넘어감 
+------------------+
| Main()           |  
+------------------+
<High Address>

**************이부분 좀 다시봐야할듯*********************

CF.
SFP(Saved Frame Pointer) :이전 함수의 스택 프레임 기준점(EBP)을 저장해서 함수가 끝날 때 스택을 정확히 복구하기위해


ex) main함수에 call A 불러왓고 소멸과정 실제 메모리 스택프레임의 예시 (더해주는예시)
leave 
혹은
MOV ESP,EBP
POP EBP


call명령어 : 그다음주소값을 레지스터에 백업해두고 함수끝나고 넘어오면서 이때 SFP가 EIP로 오버라이트되는거임
leave : ESP ->EBP , SFP ->EBP
ret : 맨상단주소 



--------
함수호출규약 : 함수를 호출할 때 인자 전달 방식, 스택 정리 방식, 레지스터 사용 규칙 등을 정하는 규칙

                cdecl            stdcall        fastcall
피연산자          스택               스택        레지스터(ECX,EDX)+스택

스택프레임        caller            callee        callee
해체
ex) sum(a,b)     push b            push b
                 push a            pushh a
                call A()           call A()
                add ESP,8          ->안쪽에서정리
                push EAX
                (스택이므로 꺼낼떄
       ->피연산자 main이처리해주는거고 



그다음 반복문들 어셈블리어로 봄

cf. CMP와 TEST
CMP A, B -> A - B (크기를비교한다면)
TEST A, B -> A & B (비트연산) (특정비트가 설정됐는지 검사하는느낌)
ex.TEST EAX, EAX -> EAX==0이맞냐? 즉 실패햇냐


-------------
03.13.금

문제2.
Main함수에서 식별되는2개의 함수(코드는다르지만같은기능)는 같은 기능을 수행하는 함수입니다.
첫 번째 함수는 인자를 어떻게 전달 받는지 파악하고, 두 번째 함수에 PUSH해야 하는 인자를 

40106D PUSH 0 인데이런식으로 어떤값이들어가야하는지 ->스페이스바로 수정



exeinfope.exe-오픈소스,실행파일의 내부분석,패킹됏냐안됏냐판단
die.exe
--
asyncRAT -> 원격접속트로이목마RAT에대한

.NETframework -> MS에서 제공하는 프레임워크(기계어x/중간언어immediately language)
도구있어야함 (CPU가이해하는언어가아니여서) ->dnSpy: .netframework 런타임도구
mscoree.dll -> Microsoft .NET Runtime Execution Engine DLL
.NET 프로그램을 실행할 때 처음 로딩되는 핵심 DLL

dnSpy : IOC정보뽑으려고
주황색:함수
청록색:클래스
보라색:변수

asyncRAT.exe올렸음 ->Main클릭
f11-step into안으로들어가지는한줄실행
f10-한줄실행\
f5- 실행
f9- 디버깅
우클릭 -show in memory window


cf.infected->보통많이함(비밀번호압축)

문제3.
rat.exe에서 IP와 PORT를 찾으시오.



onload

