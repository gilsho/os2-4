#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H



typedef int pid_t;

void process_close(int status);
pid_t process_execute (const char *file_name);
int process_wait (pid_t);
void process_exit (void);
void process_activate (void);
void process_init(void);

#endif /* userprog/process.h */
