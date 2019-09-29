/// Probabilistic Security Metric

int multiplication_factor = 20; //-------------------------------Change when req

int any_exploit_to_visit_prob()
{
    int j;
    for(j=0; j<total_no_of_nodes; j++)
    {
        if ((g[condition[stack_top_no].id][j][0] == 1) && (g[condition[stack_top_no].id][j][1] == 0))
            {
                gp = condition[stack_top_no].p;
                g[condition[stack_top_no].id][j][1] = 1;
                stack_push(j);
                fb = 1;
                return 1;
            } 
    }
    return 0;
}

float condition_prob()
{
	int i, j;
	float prob = 0;
	for (i=0; i<condition[stack_top_no].prob_pointer; i++)
	{
		prob = prob + condition[stack_top_no].probabilities[i];
	}
	
	if (condition[stack_top_no].prob_pointer == 1)
		return prob;
	
	for (i=0; i<(condition[stack_top_no].prob_pointer-1); i++)
	{
		for (j=i+1; j<condition[stack_top_no].prob_pointer; j++)
		{
			prob = prob - (condition[stack_top_no].probabilities[i])*(condition[stack_top_no].probabilities[j]);
		}
	}
	return prob;	
}


int condition_func_prob()
{
    if (fb == 1)
        {
        	condition[stack_top_no].v = condition[stack_top_no].v + 1;
        	condition[stack_top_no].probabilities[condition[stack_top_no].prob_pointer] = gp; 
        	condition[stack_top_no].prob_pointer++;
        }   
    if (condition[stack_top_no].v == condition[stack_top_no].r)
        {
            if (fb == 1)
                {
                	condition[stack_top_no].p = condition_prob();	
                  	fb = 0;
                  	//printf ("\n    prob = %f", condition[stack_top_no].p);
                } 
            if (any_exploit_to_visit_prob())
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


int any_condition_to_visit_prob()
{
    int i,j; 
    for(j=0; j<total_no_of_nodes; j++)
    {
        if ((g[stack[stack_top]][j][0] == 1) && (g[stack[stack_top]][j][1] == 0))
            {
                gp = exploit[stack_top_no].p;
                g[stack[stack_top]][j][1] = 1;
                stack_push(j);
                fb = 1;
                return 1;
            } 
    }
    return 0;
}

float exploit_prob()
{
	int i = 0;
	float prob = 1;
	for (i=0; i<exploit[stack_top_no].prob_pointer; i++)
	{
		prob = prob*exploit[stack_top_no].probabilities[i];
	}
	return prob;	
}


int exploit_func_prob()
{
	float prob = 1;
   	if (fb == 1)
        {
        	exploit[stack_top_no].v = exploit[stack_top_no].v + 1;
        	exploit[stack_top_no].probabilities[exploit[stack_top_no].prob_pointer] = gp;
        	exploit[stack_top_no].prob_pointer++;
        }
    if (exploit[stack_top_no].v == exploit[stack_top_no].r)
        {
            if (fb == 1)
                {
                	prob = exploit_prob();
                    exploit[stack_top_no].p = (exploit[stack_top_no].p)*prob;
                    fb = 0;
                    //printf ("\n    prob = %f", exploit[stack_top_no].p);
                }  
            if (any_condition_to_visit_prob())  
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


float metric_for_goal_prob()
{
    int i;
    for(i=0; i<no_of_con; i++)
    {
        if (condition[i].initialgoal == 9)
            {
                return condition[i].p;
            } 
    }
}


int func_prob()
{
    int c_or_e= 0;
    //printf("\n\n           -- Calculating Probabilistic Security --\n");
    while(1)
    {
        c_or_e = con_or_exp();
        if (stack_top==0)
            {                        
                if(any_initial_cond_left())
	                {
	                	condition_func_prob();
					}
                else
                    break;
            }
        else 
            {
                if ((c_or_e == 1) && (condition[stack_top_no].initialgoal == 1))
                    {
                        if (any_exploit_to_visit_prob());
                        else stack_pop();
                    }
                else
                    { 
                        if ((c_or_e == 1) && (condition[stack_top_no].initialgoal != 1))
                        	{
                        		condition_func_prob();
							}
                            
                        else
                            {
                                exploit_func_prob();
                            }
                    }    
            } 
    }
    
    //printf ("\n\nProbabilistic Security Metric for Goal Condition = %f\n", metric_for_goal_prob());
    met[loop_i].prob = metric_for_goal_prob()*50;
    return 1;
}

