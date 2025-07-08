#include "../flexric/src/xApp/e42_xapp_api.h"
#include <unistd.h>
#include <stdio.h>

int main(int argc,char *argv[]){

    fr_args_t arguments = init_fr_args(argc,argv);  //you can pass any initializing arguments
    init_xapp_api(&arguments);
    usleep(10000);

    e2_node_arr_xapp_t arr = e2_nodes_xapp_api();

    if(arr.len>0){
        //atleast 1 e2 node is connected
        printf("RAN function id : %d\n",arr.n[0].rf->id);
    }
    while(try_stop_xapp_api()==false) usleep(1000);   //1 ms
    free_e2_node_arr(&arr); //free the memory on finish
    
    return 0;
}
   


/*
typedef void (*sm_cb)(sm_ag_if_rd_t const*);

typedef union{
  char* reason;
  int handle;
} sm_ans_xapp_u;

typedef struct{
  sm_ans_xapp_u u;
  bool success;
} sm_ans_xapp_t;

typedef enum{
  ms_1,
  ms_2,
  ms_5,
  ms_10,
  ms_100,
  ms_1000,

  ms_end,
} inter_xapp_e;

// Returns a handle
sm_ans_xapp_t report_sm_xapp_api(global_e2_node_id_t* id, uint32_t rf_id, void* data, sm_cb handler);

// Remove the handle previously returned
void rm_report_sm_xapp_api(int const handle);

// Send control message
// return void but sm_ag_if_ans_ctrl_t should be returned. Add it in the future if needed
sm_ans_xapp_t control_sm_xapp_api(global_e2_node_id_t* id, uint32_t rf_id, void* wr);

*/