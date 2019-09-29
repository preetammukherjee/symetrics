/// Path Length Metrics

int any_exploit_to_visit_len()
{
    int j;
    for(j=0; j<total_no_of_nodes; j++)
    {
        if ((g[condition[stack_top_no].id][j][0] == 1) && (g[condition[stack_top_no].id][j][1] == 0))
            {
                glen = condition[stack_top_no].len;
                g[condition[stack_top_no].id][j][1] = 1;
                stack_push(j);
                fb = 1;
                return 1;
            } 
    }
    return 0;
}


int condition_func_len()
{
    if (fb == 1)
        {
            condition[stack_top_no].v = condition[stack_top_no].v + 1;
            if((condition[stack_top_no].len > glen) || (condition[stack_top_no].len == 0))
                condition[stack_top_no].len = glen;
        }   
    if (condition[stack_top_no].v == condition[stack_top_no].r)
        {
            if (fb == 1)
                {
                	fb = 0;
                	//printf ("\n    len = %d", condition[stack_top_no].len);	
				}
            if (any_exploit_to_visit_len())
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


int any_condition_to_visit_len()
{
    int i,j; 
    for(j=0; j<total_no_of_nodes; j++)
    {
        if ((g[stack[stack_top]][j][0] == 1) && (g[stack[stack_top]][j][1] == 0))
            {
                glen = exploit[stack_top_no].len;
                g[stack[stack_top]][j][1] = 1;
                stack_push(j);
                fb = 1;
                return 1;
            } 
    }
    return 0;
}


int exploit_func_len()
{	
   if (fb == 1)
        {
            exploit[stack_top_no].v = exploit[stack_top_no].v + 1;
            exploit[stack_top_no].len = exploit[stack_top_no].len + glen;
        }
    if (exploit[stack_top_no].v == exploit[stack_top_no].r)
        {
            if (fb == 1)
                {
					exploit[stack_top_no].len = exploit[stack_top_no].len + 1;
                    fb = 0;
                    //printf ("\n    len = %d", exploit[stack_top_no].len);
                }   
            if (any_condition_to_visit_len())  
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


int metric_for_goal_len()
{
    int i;
    for(i=0; i<no_of_con; i++)
    {
        if (condition[i].initialgoal == 9)
            {
                return condition[i].len;
            } 
    }
}


int func_len()
{
    int c_or_e= 0;
    //printf("\n\n           -- Calculating Shortest Path Length --\n");
    while(1)
    {
        c_or_e = con_or_exp();
        if (stack_top==0)
            {                        
                if(any_initial_cond_left())
	                {
	                	condition_func_len();
					}   
                else
                    break;
            }
        else 
            {
                if ((c_or_e == 1) && (condition[stack_top_no].initialgoal == 1))
                    {
                        if (any_exploit_to_visit_len());
                        else stack_pop();
                    }
                else
                    { 
                        if ((c_or_e == 1) && (condition[stack_top_no].initialgoal != 1))
                        	{
                        		condition_func_len();
							}
                            
                        else
                            {
                                exploit_func_len();
                            }
                    }    
            } 
    }
    
    //printf ("\n\nPath Length for Goal Condition = %d\n", metric_for_goal_len());
    met[loop_i].len = metric_for_goal_len();
    return 1;
}
