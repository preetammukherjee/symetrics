/// Attack Graph
#include <stdio.h>

struct metrics
    {
    	int s_no;
    	int no_of_nodes;
    	float diff;
    	float prob;
    	float res;
    	int len;
	};
int max_no_AG = 500;	// Max number of Attack Graphs
struct metrics met[500];  
int loop_i = 0;

int no_of_con = 0;  // Max number of conditions in a graph
int no_of_exp = 0;   // Max number of exploits in a graph

int INFINITY_res = 10; // value of (10/0) for Attack Resistance Metric

#include "Graph_Gen.c"

float gd = 0, gl = 0; // For Attack Difficulty Metric
float gp = 0;  // For Probabilistic Security Metric
float gr = 0;  // For Attack Resistance Metric
int glen = 0; // For Shortest Path Length Metric

int fb = 0;
int stack_top = 0;
int stack_top_no = 0;
int stack[1000];  // Initialized with 1000

#include "Diff.c"
#include "Prob.c"
#include "Res.c"
#include "Len.c"

int con_or_exp() //returning 1 when condition node and 2 when exploit node
{
    int i;
    for(i=0; i<total_no_of_exp_or_con; i++)
    {
        if (condition[i].id == stack[stack_top])
            {
                return 1;
            }
        if (exploit[i].id == stack[stack_top])
            {
                return 2;                
            }            
    }
}

int stack_push(int id)
{
    int i;
    stack_top++;
    stack[stack_top] = id;
    //printf ("\nstack_top = %d", id);    
    for(i=0; i<total_no_of_exp_or_con; i++)
    {
        if (condition[i].id == stack[stack_top])
            {
                stack_top_no = i;
                return 1;
            }
        if (exploit[i].id == stack[stack_top])
            {
                stack_top_no = i;
                return 1;                
            }            
    }
}

int stack_pop()
{
    int i;
    int id;
    fb = 0;
    if (stack_top==0)
        return -1;
    else
    {
        id = stack[stack_top];
        stack_top--;        
        for(i=0; i<total_no_of_nodes; i++)
        {
            if (condition[i].id == stack[stack_top])
                {
                    stack_top_no = i;
                    return 1;
                }
            if (exploit[i].id == stack[stack_top])
                {
                    stack_top_no = i;
                    return 1;                
                }            
        }
        return id;
    }
}

int any_initial_cond_left()
{
    int i;
    for(i=0; i<no_of_con; i++)
    {
        if ((condition[i].initialgoal == 1) && (condition[i].visited_ini == 0))
            {
                stack_push(condition[i].id);
                condition[i].visited_ini = 1;
                return 1;
            } 
    }
    return 0;
}

int initialize ()
{
	int i, j;
	
	fb = 0;
	stack_top = 0;
	stack_top_no = 0;
	for(i=0; i<total_no_of_nodes; i++)
	{
		stack[i] = 0;
	}
	
    // Initializing paths of Attack Graph
    for(i=0; i<total_no_of_nodes; i++)
    {
        for(j=0; j<total_no_of_nodes; j++)
        {
            g[i][j][1] = 0;
        }
    }
	
	// Initializing Condition Nodes
    for(i=0; i<total_no_of_exp_or_con; i++)
    {
        condition[i].d = 0;
        condition[i].l = 0;
        condition[i].v = 0;
        condition[i].visited_ini = 0;
        condition[i].td = 0;
        condition[i].fp = 0;
        condition[i].mark = 0;
        for (j=0; j<total_no_of_exp_or_con;j++)
        	{
        		condition[i].probabilities[j] = 0;
			}
		condition[i].prob_pointer = 0;
		for (j=0; j<total_no_of_exp_or_con;j++)
        	{
        		condition[i].resistances[j] = 0;
			}
		condition[i].res_pointer = 0;
    } 
    
    // Initializing Exploit Nodes
    for(i=0; i<total_no_of_exp_or_con; i++)
    {
        exploit[i].d = 0;
        exploit[i].l = 0;
        exploit[i].v = 0;
        exploit[i].td = 0;
        exploit[i].fd = 0;        
        exploit[i].fp = 0;
        exploit[i].mark = 0;
        for (j=0; j<total_no_of_exp_or_con;j++)
        	{
        		exploit[i].probabilities[j] = 0;
			}
		exploit[i].prob_pointer = 0;
		for (j=0; j<total_no_of_exp_or_con;j++)
        	{
        		exploit[i].resistances[j] = 0;
			}
		exploit[i].res_pointer = 0;
    }
    
    return 1;
}

int main()
{
    int i, j, k, loop = 0;
    FILE *fplot;  // for Plotting different Metrics
    
    for(i=0; i<max_no_AG; i++)   // No of Attack Graphs
    {
        met[i].s_no = i+1;
        met[i].no_of_nodes = 0;
        met[i].diff = 0;
        met[i].prob = 0;
        met[i].res = 0;
        met[i].len = 0;
	}
    
    char buf_graph_display[1000]; // Variable for System Call

	printf("\n\n          -- Attack Graph Generation and Metric Calculation Tool --\n");
	printf("\n\n\tHow many Attack Graphs are required?    ");
	scanf("%d",&loop);
	
	printf("\n\n\tMaximum number of Condition or Exploit nodes in the Attack Graph?    ");
	scanf("%d",&no_of_con);
	no_of_exp = no_of_con;
	
	for(loop_i = 0; loop_i < loop; loop_i++)
	{
	    // Initializing Elements of Attack Graph
	    for(i=0; i<total_no_of_nodes; i++)
	    {
	        for(j=0; j<total_no_of_nodes; j++)
	        {
	            for (k=0; k<2; k++)
	            {
	                g[i][j][k] = 0;
	            }
	        }
	    }
	    
	    // Initializing Condition nodes
	    for(i=0; i<total_no_of_exp_or_con; i++)
	    {
	        // No Initialization again
	        condition[i].id = -1;
			condition[i].initialgoal = 0;
	        condition[i].r = 0;
	        condition[i].p = 1;
	        condition[i].res = 0;
	        condition[i].len = 0;
	        
	        // Initialize again
	        condition[i].d = 0;
	        condition[i].l = 0;
	        condition[i].v = 0;
	        condition[i].visited_ini = 0;
	        condition[i].td = 0;
	        condition[i].fp = 0;
	        condition[i].mark = 0;
	        for (j=0; j<total_no_of_exp_or_con;j++)
	        	{
	        		condition[i].probabilities[j] = 0;
				}
			condition[i].prob_pointer = 0;
			for (j=0; j<total_no_of_exp_or_con;j++)
	        	{
	        		condition[i].resistances[j] = 0;
				}
			condition[i].res_pointer = 0;
	    } 
	    
	    // Initializing Exploit nodes
	    for(i=0; i<total_no_of_exp_or_con; i++)
	    {
	        // No Initialization again
	        exploit[i].id = -1;	        
			exploit[i].cvss = 0;
	        exploit[i].r = 0;
	        exploit[i].ri = 0;
	        exploit[i].p = 1;
	        exploit[i].res = 0;
	        exploit[i].len = 0;
	        
	        // Initialize again
	        exploit[i].d = 0;
	        exploit[i].l = 0;
	        exploit[i].v = 0;
	        exploit[i].td = 0;
	        exploit[i].fd = 0;        
	        exploit[i].fp = 0;
	        exploit[i].mark = 0;
	        for (j=0; j<total_no_of_exp_or_con;j++)
	        	{
	        		exploit[i].probabilities[j] = 0;
				}
			exploit[i].prob_pointer = 0;
			for (j=0; j<total_no_of_exp_or_con;j++)
	        	{
	        		exploit[i].resistances[j] = 0;
				}
			exploit[i].res_pointer = 0;
	    }
	
		printf("\n\n           -- Generating Graph %d --\n", loop_i+1);
	    Graph_Gen();
	
		// Displaying Graph
		sprintf(buf_graph_display, "F:\\PhD\\Thesis\\RES_CODE\\GraphViz\\release\\bin\\dot.exe -Tpng F:\\PhD\\Thesis\\RES_CODE\\TEMP\\ag_dot.dot -o F:\\PhD\\Thesis\\RES_CODE\\TEMP\\AG%d.png", loop_i+1);
	    system(buf_graph_display);
    	sprintf(buf_graph_display, "start chrome F:\\PhD\\Thesis\\RES_CODE\\TEMP\\AG%d.png", loop_i+1);
    	system(buf_graph_display);

    	sprintf(buf_graph_display, "ren F:\\PhD\\Thesis\\RES_CODE\\TEMP\\ag_xml.xml AG%d.xml", loop_i+1);
    	system(buf_graph_display);
	    
	    // Inserting Parameters Important to Respective Metrics
	    // Inserting value of Probabilistic Security 
		for(i=0; i<total_no_of_exp_or_con; i++)
	    {
	        exploit[i].p = (exploit[i].cvss)/10;
	    }
	    
	    //Inserting Value of Attack Resistance 	    
		for(i=0; i<total_no_of_exp_or_con; i++)
	    {
	    	if (exploit[i].cvss >= 1)
	        	exploit[i].res = 10/(exploit[i].cvss);
	        else exploit[i].res = INFINITY_res;	// TO GET RID OF INFINITY
	    }    
	    
	    printf("\n\n           -- Calculating Measurements on the Generated Attack Graph --\n");
	    
	    // Flushing all the Temp Variables
	    initialize();
	    
	    //Calculate Attack Difficulty
	    func_diff();
	    
	    // Flushing all the Temp Variables
	    initialize();
	    
	    //Calculate Probabilistic Security
	    func_prob();
		
		// Flushing all the Temp Variables
	    initialize();
	    
	    //Calculate Attack Resistance
	    func_res();
		
		// Flushing all the Temp Variables
	    initialize();
	    
	    //Calculate Shortest Path Length
	    func_len();
	}


	fplot = fopen("F:\\PhD\\Thesis\\RES_CODE\\TEMP\\met_nodes.dat", "w+");  // for Plotting Different Metrics

	printf("\n\n                       -- Summary of results for different attack graph based security metrics --\n");
	printf("\n\n\tAttack Graph\tAttack Difficulty\tProbabilistic Security (Scaled)\t\tAttack Resistance\tMin Path Length");
	fprintf(fplot, "\tAttack.Graph\tAttack.Difficulty\tProbabilistic.Security(Scaled)\t\tAttack.Resistance\tMin.Path.Length\n");
	
	for(i = 0; i < loop; i++)
	{
		printf("\n\tAG%d\t\t%f\t\t%f\t\t\t\t%f\t\t%d", i+1, met[i].diff, met[i].prob, met[i].res, met[i].len);
		fprintf(fplot, "\tAG%d\t\t%f\t\t%f\t\t\t\t%f\t\t%d\n", i+1, met[i].diff, met[i].prob, met[i].res, met[i].len);
	}
		
	printf("\n\n\n");
	fclose(fplot);  // Plotting Different Metrics
	
 	system("F:\\PhD\\Thesis\\RES_CODE\\GNUPLOT\\gnuplot\\bin\\gnuplot F:\\PhD\\Thesis\\RES_CODE\\Attack_Graph_Gen\\gnu_script.plot > F:\\PhD\\Thesis\\RES_CODE\\TEMP\\plot.svg");
    system("start chrome F:\\PhD\\Thesis\\RES_CODE\\TEMP\\plot.svg");

    return 1;
}
