//#include "../vmlinux.h"
#include "stdio.h"
#include <string.h>

int strncmp_(const char *s1, const char *s2, size_t count) {
  size_t i = 0;
  while (i < count) {
    if (s1[i] != 0 && s2[i] != 0) {
      if (s1[i] == s2[i]) {
        i++;
      } else {
        return -1;
      }
    } else {
      return -1;
    }
  }
  return 0;
}

int strncmp2(const char *s1, const char *s2, size_t count) {
  if (s1 == NULL || s2 == NULL) {
    return -1;
  }
  int i = 0;
  while (1) {
    if (i == count) {
      return 0;
    }
    char ch1 = s1[i];
    char ch2 = s2[i];
    if (ch1 == '\0' || ch2 == '\0') {
      return -1;
    }
    if (ch1 == ch2) {
      i++;
      if (ch1 == '\0') {
        return 0;
      }
    } else {
      return -1;
    }
  }
  return 0;
}

int strncmp3(const char *s1, const char *s2, size_t n) {
  if (n == 0)
    return (0);
  do {
    if (*s1 != *s2++)
      return (*(unsigned char *)s1 - *(unsigned char *)--s2);
    if (*s1++ == 0)
      break;
  } while (--n != 0);
  return (0);
}

void test1() {
  int ret =
      strncmp3("/home/vimalkum/src/ebpf/learnbpf/bpftrace/first/junk.txt",
               "/home/vimalkum/src/ebpf/learnbpf/bpftrace/firs",
               sizeof("/home/vimalkum/src/ebpf/learnbpf/bpftrace/firs") - 1);
  printf("ret %d\n", ret);
}

struct TestCase {
  char *ch1;
  char *ch2;
  int num;
};

void runTests(struct TestCase tests[], int numTests) {
  for (int i = 0; i < numTests; i++) {
    struct TestCase *t = &tests[i];
    int ret = strncmp3(t->ch1, t->ch2, t->num);
    int expectedResult = strncmp(t->ch1, t->ch2, t->num);
    if (ret != expectedResult) {
      printf("Test Failed:\n");
      printf("ch1: \"%s\"\n", t->ch1);
      printf("ch2: \"%s\"\n", t->ch2);
      printf("num: %d\n", t->num);
      printf("test failed. result: %d, expectedResult: %d\n", ret,
             expectedResult);
    }
  }
}

void doTest() {
  struct TestCase tests[1];
  tests[0].ch1 = "";
  tests[0].ch2 = "";
  tests->num = 1;
  runTests(tests, 1);
}

int main(int argc, char **argv) {
  test1();
  // doTest();
  return 0;
}

typedef long (*myfunc)(long, long, long, long);

void mytest() {
  myfunc abc = 0;
  abc(0, 0, 0, 0);
}
