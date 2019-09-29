/// Attack resistance Metric


int any_exploit_to_visit_res()
{
    int j;
    for(j=0; j<total_no_of_nodes; j++)
    {
        if ((g[condition[stack_top_no].id][j][0] == 1) && (g[condition[stack_top_no].id][j][1] == 0))
            {
                gr = condition[stack_top_no].res;
                g[condition[stack_top_no].id][j][1] = 1;
                stack_push(j);
                fb = 1;
                return 1;
            } 
    }
    return 0;
}

float condition_res()
{
	int i, j;
	float res_t = 0, res = 0;
	for (i=0; i<condition[stack_top_no].res_pointer; i++)
	{
		res_t = res_t + (1/condition[stack_top_no].resistances[i]);
	}
	
	res = 1/res_t;
	
	return res;	
}


int condition_func_res()
{
    if (fb == 1)
        {
        	condition[stack_top_no].v = condition[stack_top_no].v + 1;
        	condition[stack_top_no].resistances[condition[stack_top_no].res_pointer] = gr; 
        	condition[stack_top_no].res_pointer++;
        }   
    if (condition[stack_top_no].v == condition[stack_top_no].r)
        {
            if (fb == 1)
                {
                	condition[stack_top_no].res = condition_res();	
                  	fb = 0;
                  	//printf ("\n    res = %f", condition[stack_top_no].res);
                } 
            if (any_exploit_to_visit_res())
                return 1;
            else
                {
                    stack_pop();
                    return 1;
                }
        }        
    else
        {
            stack_pop();
            return 1;        
        }
    return 1;
}



int any_condition_to_visit_res()
{
    int i,j; 
    for(j=0; j<total_no_of_nodes; j++)
    {
        if ((g[stack[stack_top]][j][0] == 1) && (g[stack[stack_top]][j][1] == 0))
            {
                gr = exploit[stack_top_no].res;
                g[stack[stack_top]][j][1] = 1;
                stack_push(j);
                fb = 1;
                return 1;
            } 
    }
    return 0;
}

float exploit_res()
{
	int i = 0;
	float res = 0;
	for (i=0; i<exploit[stack_top_no].res_pointer; i++)
	{
		res = res + exploit[stack_top_no].resistances[i];
	}
	return res;	
}


int exploit_func_res()
{
	float res = 0;
   	if (fb == 1)
        {
        	exploit[stack_top_no].v = exploit[stack_top_no].v + 1;
        	exploit[stack_top_no].resistances[exploit[stack_top_no].res_pointer] = gr;
        	exploit[stack_top_no].res_pointer++;
        }
    if (exploit[stack_top_no].v == exploit[stack_top_no].r)
        {
            if (fb == 1)
                {
                	res = exploit_res();
                    exploit[stack_top_no].res = exploit[stack_top_no].res + res;
                    fb = 0;
                    //printf ("\n    res = %f", exploit[stack_top_no].res);
                }   
            if (any_condition_to_visit_res())  
                return 1;
            else
                {
                    stack_pop();
                    return 1;
                }
        }
    else
        {
            stack_pop();
            return 1;
        }
}


float metric_for_goal_res()
{
    int i;
    for(i=0; i<no_of_con; i++)
    {
        if (condition[i].initialgoal == 9)
            {
                return condition[i].res;
            } 
    }
}


int func_res()
{
    int c_or_e = 0;
    //printf("\n\n           -- Calculating Attack Resistance --\n");
    while(1)
    {
        c_or_e = con_or_exp();
        if (stack_top==0)
            {                        
                if(any_initial_cond_left())
	                {
	                	condition_func_res();
					}
                else
                    break;
            }
        else 
            {
                if ((c_or_e == 1) && (condition[stack_top_no].initialgoal == 1))
                    {
                        if (any_exploit_to_visit_res());
                        else stack_pop();
                    }
                else
                    { 
                        if ((c_or_e == 1) && (condition[stack_top_no].initialgoal != 1))
                        	{
                        		condition_func_res();
							}
                            
                        else
                            {
                                exploit_func_res();
                            }
                    }    
            }  
    }
    
    //printf ("\n\nAttack resistance Metric for Goal Condition = %f\n", metric_for_goal_res());
    met[loop_i].res = metric_for_goal_res();
    return 1;
}


