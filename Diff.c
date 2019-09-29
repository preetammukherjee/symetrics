/// Attack Difficulty metric

int any_exploit_to_visit_diff()
{
    int j;
    for(j=0; j<total_no_of_nodes; j++)
    {
        if ((g[condition[stack_top_no].id][j][0] == 1) && (g[condition[stack_top_no].id][j][1] == 0))
            {
                gd = condition[stack_top_no].d;
                gl = condition[stack_top_no].fp;
                g[condition[stack_top_no].id][j][1] = 1;
                stack_push(j);
                fb = 1;
                return 1;
            } 
    }
    return 0;
}


int condition_func_diff()
{
	float w1 = 0.0, w2 = 0.0, w3 =0.0, w4 = 0.0, w5 = 0.0;
	
    if (fb == 1)
        {
            condition[stack_top_no].v = condition[stack_top_no].v + 1;
            if((gd < condition[stack_top_no].d) || (condition[stack_top_no].l == 0))
                {
                    condition[stack_top_no].d = gd;
                    condition[stack_top_no].l = gl;
                }
            else
                {
                    if ((gd == condition[stack_top_no].d) || (gl < condition[stack_top_no].l))
                    condition[stack_top_no].l = gl;
                }
            condition[stack_top_no].td = condition[stack_top_no].td + gd;    
        }   
    if (condition[stack_top_no].v == condition[stack_top_no].r)
        {
            if (fb == 1)
                {
                	if((condition[stack_top_no].r - 1)==0)
                		condition[stack_top_no].fp = condition[stack_top_no].l;
                  	else
                  	{
						  w1 = condition[stack_top_no].r;
						  w2 = (w1 - 1)/w1;
						  w3 = condition[stack_top_no].d*(w1 - 1);
						  w4 = condition[stack_top_no].td - condition[stack_top_no].d;
						  w5 = w2*w3;
						  condition[stack_top_no].fp = condition[stack_top_no].l - w5/w4;
					}	
                  fb = 0;
                  //printf ("\n    diff = %f", gd);
                }
            if (any_exploit_to_visit_diff())
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


int any_condition_to_visit_diff()
{
    int i,j; 
    for(j=0; j<total_no_of_nodes; j++)
    {
        if ((g[stack[stack_top]][j][0] == 1) && (g[stack[stack_top]][j][1] == 0))
            {
                gd = exploit[stack_top_no].fd;
                gl = exploit[stack_top_no].fp;
                g[stack[stack_top]][j][1] = 1;
                stack_push(j);
                fb = 1;
                return 1;
            } 
    }
    return 0;
}


int exploit_func_diff()
{
	float w1 = 0.0, w2 = 0.0, w3 = 0.0, w4 = 0.0, w5 = 0.0, w6 = 0.0;
	
   if (fb == 1)
        {
            exploit[stack_top_no].v = exploit[stack_top_no].v + 1;
            if(gd > exploit[stack_top_no].d)
                {
                    exploit[stack_top_no].d = gd;
                    exploit[stack_top_no].l = gl;
                }
            else
                {
                    if ((gd == exploit[stack_top_no].d) && (gl > exploit[stack_top_no].l))
                        exploit[stack_top_no].l = gl;
                }
            exploit[stack_top_no].td = exploit[stack_top_no].td + gd;
        }
    if (exploit[stack_top_no].v == exploit[stack_top_no].r)
        {
            if (fb == 1)
                {
                    if ((exploit[stack_top_no].r - exploit[stack_top_no].ri) > 1)
                        {
                        	w3 = (exploit[stack_top_no].r - exploit[stack_top_no].ri) - 1;
                        	w4 = exploit[stack_top_no].r - exploit[stack_top_no].ri;
                        	w1 = w3/w4;
                        	w5 = exploit[stack_top_no].d;
                        	w6 = exploit[stack_top_no].td - exploit[stack_top_no].d;
                        	w2 = (w6)/(w5*w3);
                            exploit[stack_top_no].fp = (exploit[stack_top_no].l + 1) + (w1*w2);
                        }
                    else exploit[stack_top_no].fp = exploit[stack_top_no].l + 1;
                    exploit[stack_top_no].fd = (((10 - exploit[stack_top_no].cvss)/10)*exploit[stack_top_no].fp) + exploit[stack_top_no].td;
                    fb = 0;
                    //printf ("\n    diff = %f", exploit[stack_top_no].fd);
                }  
            if (any_condition_to_visit_diff())  
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


float metric_for_goal_diff()
{
    int i;
    for(i=0; i<no_of_con; i++)
    {
        if (condition[i].initialgoal == 9)
            {
                return condition[i].d;
            } 
    }
}


int func_diff()
{
    int c_or_e= 0;
    
    //printf("\n\n           -- Calculating Attack Difficulty --\n");
    
    while(1)
    {
        c_or_e = con_or_exp();
        if (stack_top==0)
            {                        
                if(any_initial_cond_left())
	                {
	                	condition_func_diff();
					}
                    
                else
                    break;
            }
        else 
            {
                if ((c_or_e == 1) && (condition[stack_top_no].initialgoal == 1))
                    {
                        if (any_exploit_to_visit_diff());
                        else stack_pop();
                    }
                else
                    { 
                        if ((c_or_e == 1) && (condition[stack_top_no].initialgoal != 1))
                        	{
                        		condition_func_diff();
							}
                            
                        else
                            {
                                exploit_func_diff();
                            }
                    }    
            }
    }
    
    //printf ("\n\nAttack Difficulty for Goal Condition = %f\n", metric_for_goal_diff());
    met[loop_i].diff = metric_for_goal_diff();
    return 1;
}


