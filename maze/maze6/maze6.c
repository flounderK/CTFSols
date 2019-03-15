
int main(int argc,char **argv)

{
  FILE *__stream;
  size_t __n;
  char buf [256];
  FILE *fp;
  
  if (argc != 3) {
    printf("%s file2write2 string\n",*argv);
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  __stream = fopen(argv[1],"a");
  if (__stream == (FILE *)0x0) {
    perror("fopen");
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  strcpy(buf,argv[2]);
  __n = strlen(buf);
  memfrob(buf,__n);
  fprintf(__stream,"%s : %s\n",argv[1],buf);
                    /* WARNING: Subroutine does not return */
  exit(0);
}

