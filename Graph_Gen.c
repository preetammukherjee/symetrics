//Code to Generate an Attack Graph

// to make dot file
FILE *fp_dot_path;
FILE *fp_dot_node;

FILE *fp_xml_path;
FILE *fp_xml_node;

int total_no_of_nodes = 1000, total_no_of_exp_or_con = 500;  // Initialized as required
int no_of_incoming_edges = 500; // Number of Incoming edges to a node

int g[1000][1000][2]; // Two layers : one for attack graph and another for storing temporary traversal for each individual case
struct con{
    int id;
    int initialgoal;
    float d;
    float l;
    int v;
    int visited_ini;
    float td;
    float fp;
    int r;
    int mark;
    
    float p;
    float probabilities[500]; //no_of_incoming_edges
    int prob_pointer;
    
    float res;
    float resistances[500]; //no_of_incoming_edges
    int res_pointer;
    
    int len;
    };
struct con condition[500]; //total_no_of_exp_or_con

struct explo{
    int id;
    float cvss;
    float d;
    float l;
    int v;
    float td;
    float fd;
    float fp;
    int r;
    int ri;
    int mark;
    
    float p;
    float probabilities[500];  // no_of_incoming_edges
    int prob_pointer;

    float res;
    float resistances[500];  // no_of_incoming_edges
    int res_pointer;
    
    int len;
    };
struct explo exploit[500]; //total_no_of_exp_or_con

time_t t;
int no_of_con_used = 0;
int goal;

int not_previous(int start_id,int check_id)
{
	int i=0;
	for(i=0;i<no_of_con+no_of_exp;i++)
	{
		if (g[i][start_id][0]==1)
			{
				if(check_id == i)
				{
					return 0;
				}
				if(not_previous(i,check_id)	== 0)
				{
					return 0;
				}
			}
	}
	return 1;
}

int exist(int perct_70_of_total_nodes_rand)
{  
    // to maintain the line without loop
    struct con local_condition[no_of_con]; 
    struct explo local_exploit[no_of_exp];
	   
	int br = 0, i = 0,j = 0, max = 0, con_id = 0, exp_id = 0, id =0, start_id = 0, temp = 0;
	float cvss1 = 0.0, cvss2 = 0.0;
	int stuck_breaker = 0;  // When got stuck
	
	//Flushing local list of conditions and exploits
	for(i=0; i<no_of_con; i++)
    {
        local_condition[i].mark = 0;
    }
    for(i=0; i<no_of_exp; i++)
    {
        local_exploit[i].mark = 0;        
    }
	    
    // First node from the set of Existing nodes
	while(br==0)
	{
		temp = 	no_of_con + no_of_exp;
		id = rand()%temp;		
		if (id < no_of_con)
		{
			if(id == goal)
				continue;
			if(condition[id].mark == 1)
				{
					//printf("\nexisting condition id %d", id);
					fprintf(fp_dot_path, "C%d->",id); // for storing Attack Graph in .dot format
					con_id = id;
					start_id = id;
					local_condition[con_id].mark = 1;
					br = 1;
					max=0;
				}				
		}
		else
		{ 
			for(i=0; i<no_of_con; i++)  // last Exploit detection
				{
					if(g[id][i][0] == 1)
					{
					    if(i == goal)
					    	stuck_breaker = 1;
					    else
					    {
					    	stuck_breaker = 0;
					    	break;
						}			
					}      
				}
			    
			if((stuck_breaker == 0) && (exploit[id - no_of_con].mark == 1)) // if last Exploit then discarded
				{
					//printf("\nexisting exploit id %d", id);
					fprintf(fp_dot_path, "E%d->",id); // for storing Attck Graph in .dot format
					exp_id = id;
					start_id = id;
					local_exploit[exp_id - no_of_con].mark = 1;
					max=1;
					br = 1;					
				}				
		}	
	}
	br=0;
	i = 0;	// no of nodes in the path
	// loop of node starts	
	while (i<perct_70_of_total_nodes_rand)
	{
		if (max == 1)
			{
				while(br==0)
				{		
					con_id = rand()%no_of_con;
					if(local_condition[con_id].mark == 1)
						continue;
					if(condition[con_id].initialgoal == 1)	
						continue;									
					if(condition[con_id].mark == 1)
					{
						if(not_previous(start_id,con_id))
						{
							g[exp_id][con_id][0] = 1;
							fprintf(fp_xml_path, "\t\t<link>\n\t\t\t<source id=\"%d\"/>\n",exp_id); // for storing Attack Graph in .xml format
							fprintf(fp_xml_path, "\t\t\t<destination id=\"%d\"/>\n\t\t</link>\n",con_id); // for storing Attack Graph in .xml format
							//printf("\nattached to existing condition id %d", con_id);
							fprintf(fp_dot_path, "C%d;\n",con_id); // for storing Attack Graph in .dot format
							return 1;
						}
						else
							continue;					
					}
					br = 1;
					max = 0;
					//printf("\ncondition id %d", con_id);
					fprintf(fp_dot_path, "C%d->",con_id); // for storing Attack Graph in .dot format
					condition[con_id].mark = 1;
					condition[con_id].id = con_id;
					local_condition[con_id].mark = 1;
					no_of_con_used++;					
				}
				g[exp_id][con_id][0] = 1;
				fprintf(fp_xml_path, "\t\t<link>\n\t\t\t<source id=\"%d\"/>\n",exp_id); // for storing Attack Graph in .xml format
				fprintf(fp_xml_path, "\t\t\t<destination id=\"%d\"/>\n\t\t</link>\n",con_id); // for storing Attack Graph in .xml format				
				br = 0;	
			}
		else
			{
				while(br==0)
				{		
					exp_id = rand()%no_of_exp;
					exp_id = exp_id + no_of_con;
					if(local_exploit[exp_id - no_of_con].mark == 1)
						continue;								
					if(exploit[exp_id - no_of_con].mark == 1)
					{
						if(not_previous(start_id,exp_id))
							{
								g[con_id][exp_id][0] = 1;
								fprintf(fp_xml_path, "\t\t<link>\n\t\t\t<source id=\"%d\"/>\n",con_id); // for storing Attack Graph in .xml format
								fprintf(fp_xml_path, "\t\t\t<destination id=\"%d\"/>\n\t\t</link>\n",exp_id); // for storing Attack Graph in .xml format					
								//printf("\nattached to existing exploit id %d", exp_id);
								fprintf(fp_dot_path, "E%d;\n",exp_id); // for storing Attack Graph in .dot format
								return 1;
							}
						else
							continue;	
					}
					br = 1;
					max = 1;
					//printf("\nexploit id %d", exp_id);
					fprintf(fp_dot_path, "E%d->",exp_id); // for storing Attack Graph in .dot format
					exploit[exp_id - no_of_con].id = exp_id;
					exploit[exp_id - no_of_con].mark = 1;
					cvss1 = rand()%10;
					cvss2 = rand()%10;
					exploit[exp_id - no_of_con].cvss = cvss1 + (cvss2/10);
					local_exploit[exp_id - no_of_con].mark = 1;					
				}
				g[con_id][exp_id][0] = 1;
				fprintf(fp_xml_path, "\t\t<link>\n\t\t\t<source id=\"%d\"/>\n",con_id); // for storing Attack Graph in .xml format
				fprintf(fp_xml_path, "\t\t\t<destination id=\"%d\"/>\n\t\t</link>\n",exp_id); // for storing Attack Graph in .xml format				
				br = 0;
			}
			i++; // no of nodes in path	
	}
	// last node to attach again
	if (max == 1)
		{
			while(br==0)
				{		
					con_id = rand()%no_of_con;
					if(local_condition[con_id].mark == 1)
						continue;
					if(condition[con_id].initialgoal == 1)	
						continue;									
					if(condition[con_id].mark == 1)
					{
						if(not_previous(start_id,con_id))
						{
							g[exp_id][con_id][0] = 1;
							fprintf(fp_xml_path, "\t\t<link>\n\t\t\t<source id=\"%d\"/>\n",exp_id); // for storing Attack Graph in .xml format
							fprintf(fp_xml_path, "\t\t\t<destination id=\"%d\"/>\n\t\t</link>\n",con_id); // for storing Attack Graph in .xml format	
							//printf("\nattached to existing condition id %d", con_id);
							fprintf(fp_dot_path, "C%d;\n",con_id); // for storing Attack Graph in .dot format
							return 1;
						}					
					}					
				}
		}
	else
		{
			while(br==0)
				{
					exp_id = rand()%no_of_exp;
					exp_id = exp_id + no_of_con;
					if(local_exploit[exp_id - no_of_con].mark == 1)
						continue;
					if(exploit[exp_id - no_of_con].mark == 1)
					{
						if(not_previous(start_id,exp_id))
							{
								g[con_id][exp_id][0] = 1;
								fprintf(fp_xml_path, "\t\t<link>\n\t\t\t<source id=\"%d\"/>\n",con_id); // for storing Attack Graph in .xml format
								fprintf(fp_xml_path, "\t\t\t<destination id=\"%d\"/>\n\t\t</link>\n",exp_id); // for storing Attack Graph in .xml format
								//printf("\nattached to existing Exploit id %d", exp_id);
								fprintf(fp_dot_path, "E%d;\n",exp_id); // for storing Attack Graph in .dot format
								return 1;
							}		
					}	
				}
		}	
	return 1;	
}

int initial(int perct_70_of_total_nodes_rand)
{  
    // to maintain the line wthout loop
    struct con local_condition[no_of_con]; 
    struct explo local_exploit[no_of_exp];    
	int br = 0, i,j, con_id = 0, exp_id = 0;
	float cvss1 = 0.0, cvss2 = 0.0;
	
	//flushing local list of Conditions and Exploits
	for(i=0; i<no_of_con; i++)
    {
        local_condition[i].mark = 0;
    }
    for(i=0; i<no_of_exp; i++)
    {
        local_exploit[i].mark = 0;        
    }
	
	while(br==0)
	{		
		con_id = rand()%no_of_con;		
		if(condition[con_id].mark == 1)
			continue;
		br = 1;
		//printf("\ncondition id %d", con_id);
		fprintf(fp_dot_path, "C%d->",con_id); // for storing Attack Graph in .dot format
		condition[con_id].mark = 1;
		condition[con_id].id = con_id;
		local_condition[con_id].mark = 1;
		condition[con_id].initialgoal = 1;
		no_of_con_used++;			
	}
	br=0;	
	for (i=0;i<perct_70_of_total_nodes_rand/2;i++)
	{
		while(br==0)
		{		
			exp_id = rand()%no_of_exp;
			exp_id = exp_id + no_of_con;
			if(local_exploit[exp_id - no_of_con].mark == 1)
				continue;								
			if(exploit[exp_id - no_of_con].mark == 1)
			{
				g[con_id][exp_id][0] = 1;
				fprintf(fp_xml_path, "\t\t<link>\n\t\t\t<source id=\"%d\"/>\n",con_id); // for storing Attack Graph in .xml format
				fprintf(fp_xml_path, "\t\t\t<destination id=\"%d\"/>\n\t\t</link>\n",exp_id); // for storing Attack Graph in .xml format
				//printf("\nattached to existing exploit id %d", exp_id);
				fprintf(fp_dot_path, "E%d;\n",exp_id); // for storing Attack Graph in .dot format
				return 1;			
			}
			br = 1;
			//printf("\nexploit id %d", exp_id);
			fprintf(fp_dot_path, "E%d->",exp_id); // for storing Attack Graph in .dot format
			exploit[exp_id - no_of_con].id = exp_id;
			exploit[exp_id - no_of_con].mark = 1;
			cvss1 = rand()%10;
			cvss2 = rand()%10;
			exploit[exp_id - no_of_con].cvss = cvss1 + (cvss2/10);
			local_exploit[exp_id - no_of_con].mark = 1;					
		}
		g[con_id][exp_id][0] = 1;
		fprintf(fp_xml_path, "\t\t<link>\n\t\t\t<source id=\"%d\"/>\n",con_id); // for storing Attack Graph in .xml format
		fprintf(fp_xml_path, "\t\t\t<destination id=\"%d\"/>\n\t\t</link>\n",exp_id); // for storing Attack Graph in .xml format			
		br=0;
		while(br==0)
		{		
			con_id = rand()%no_of_con;
			if(local_condition[con_id].mark == 1)
				continue;
			if(condition[con_id].initialgoal == 1)	
				continue;					
			if(condition[con_id].mark == 1)
			{
				g[exp_id][con_id][0] = 1;
				fprintf(fp_xml_path, "\t\t<link>\n\t\t\t<source id=\"%d\"/>\n",exp_id); // for storing Attack Graph in .xml format
				fprintf(fp_xml_path, "\t\t\t<destination id=\"%d\"/>\n\t\t</link>\n",con_id); // for storing Attack Graph in .xml format
				//printf("\nattached to existing condition id %d", con_id);
				fprintf(fp_dot_path, "C%d;\n", con_id); // for storing Attack Graph in .dot format
				return 1;				
			}
			br = 1;
			//printf("\ncondition id %d", con_id);
			fprintf(fp_dot_path, "C%d->",con_id); // for storing Attack Graph in .dot format
			condition[con_id].id = con_id;
			condition[con_id].mark = 1;	
			local_condition[con_id].mark = 1;
			no_of_con_used++;					
		}
		g[exp_id][con_id][0] = 1;
		fprintf(fp_xml_path, "\t\t<link>\n\t\t\t<source id=\"%d\"/>\n",exp_id); // for storing Attack Graph in .xml format
		fprintf(fp_xml_path, "\t\t\t<destination id=\"%d\"/>\n\t\t</link>\n",con_id); // for storing Attack Graph in .xml format				
		br=0;	
	}
	// last piece
	while(br==0)
	{		
		exp_id = rand()%no_of_exp;
		exp_id = exp_id + no_of_con;
		if(local_exploit[exp_id - no_of_con].mark == 1)
			continue;								
		if(exploit[exp_id - no_of_con].mark == 1)
		{
			g[con_id][exp_id][0] = 1;
			fprintf(fp_xml_path, "\t\t<link>\n\t\t\t<source id=\"%d\"/>\n",con_id); // for storing Attack Graph in .xml format
			fprintf(fp_xml_path, "\t\t\t<destination id=\"%d\"/>\n\t\t</link>\n",exp_id); // for storing Attack Graph in .xml format
			//printf("\nattached to existing exploit id %d", exp_id);
			fprintf(fp_dot_path, "E%d;\n",exp_id); // for storing Attack Graph in .dot format
			return 1;	
		}				
	}
	return 1;	
}

int mainline(int total_nodes_rand)
{
	int br = 0, i,j, con_id = 0, exp_id = 0;
	float cvss1 = 0.0, cvss2 = 0.0;
	while(br==0)
	{		
		con_id = rand()%no_of_con;
		if(condition[con_id].mark == 1)
			continue;
		br = 1;
		//printf("\ncondition id %d", con_id);
		fprintf(fp_dot_path, "C%d",con_id); // for storing Attack Graph in .dot format
		condition[con_id].id = con_id;
		condition[con_id].mark = 1;
		condition[con_id].initialgoal = 1;
		no_of_con_used++;	
	}
	exp_id = rand()%no_of_exp;
	br=0;	
	for (i=0;i<total_nodes_rand/2;i++)
	{
		fprintf(fp_dot_path, "->"); // for storing Attack Graph in .dot format
		while(br==0)
		{		
			exp_id = rand()%no_of_exp;
			exp_id = exp_id + no_of_con;
			if(exploit[exp_id - no_of_con].mark == 1)
				continue;
			br = 1;
			//printf("\nexploit id %d", exp_id);
			fprintf(fp_dot_path, "E%d->",exp_id);  // for storing Attack Graph in .dot format
			exploit[exp_id - no_of_con].id = exp_id;
			exploit[exp_id - no_of_con].mark = 1;
			cvss1 = rand()%10;
			cvss2 = rand()%10;
			exploit[exp_id - no_of_con].cvss = cvss1 + (cvss2/10);		
		}
		g[con_id][exp_id][0] = 1;
		fprintf(fp_xml_path, "\t\t<link>\n\t\t\t<source id=\"%d\"/>\n",con_id); // for storing Attack Graph in .xml format
		fprintf(fp_xml_path, "\t\t\t<destination id=\"%d\"/>\n\t\t</link>\n",exp_id); // for storing Attack Graph in .xml format	
		br=0;
		while(br==0)
		{		
			con_id = rand()%no_of_con;
			if(condition[con_id].mark == 1)
				continue;
			br = 1;
			//printf("\ncondition id %d", con_id);
			fprintf(fp_dot_path, "C%d",con_id);  // for storing Attack Graph in .dot format
			condition[con_id].id = con_id;
			condition[con_id].mark = 1;
			no_of_con_used++;		
		}
		g[exp_id][con_id][0] = 1;
		fprintf(fp_xml_path, "\t\t<link>\n\t\t\t<source id=\"%d\"/>\n",exp_id); // for storing Attack Graph in .xml format
		fprintf(fp_xml_path, "\t\t\t<destination id=\"%d\"/>\n\t\t</link>\n",con_id); // for storing Attack Graph in .xml format
		br=0;	
	}
	condition[con_id].initialgoal = 9;
	fprintf (fp_dot_path, ";\n"); // for storing Attack Graph in .dot format 
	goal = con_id;
	return 1;
}

int Graph_Gen()
{
	int i = 0, j = 0, k = 0, bi_rand = 0, total_nodes = 0, total_nodes_rand = 0, perct_30_of_total_nodes_int = 0, perct_30_of_total_nodes_rand = 0, perct_70_of_total_nodes_int = 0, perct_70_of_total_nodes_rand = 0;
	float perct_30_of_total_nodes = 0.0, perct_70_of_total_nodes = 0.0;
	int nodes = 0;
	//FILE *fp;  // for storing Adjacency matrix
	FILE *fp_dot; // to generate the Attack Graph in .dot format
	FILE *fp_xml; // to generate the Attack Graph in .xml format
	char c; // to generate the Attack Graph in .dot format
	
    //initialization
    srand((unsigned) time(&t));
    
	total_nodes = (no_of_con+no_of_exp);
	total_nodes_rand = rand()%total_nodes;
	if (total_nodes_rand < 2)
		total_nodes_rand = total_nodes_rand + 2;

	// to generate the Attack Graph in .dot format	 		
	fp_dot_node = fopen("F:\\PhD\\Thesis\\RES_CODE\\TEMP\\ag_dot_n.dot", "w+"); 	
    fprintf(fp_dot_node, "Digraph new{\n");
    
	fp_dot_path = fopen("F:\\PhD\\Thesis\\RES_CODE\\TEMP\\ag_dot_p.dot", "w+");
	
	fp_dot = fopen("F:\\PhD\\Thesis\\RES_CODE\\TEMP\\ag_dot.dot", "w+");

	// to generate the Attack Graph in .xml format
	fp_xml_node = fopen("F:\\PhD\\Thesis\\RES_CODE\\TEMP\\ag_xml_n.xml", "w+");	
    fprintf(fp_xml_node, "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<AttackGraph>\n<nodes>\n");
    
	fp_xml_path = fopen("F:\\PhD\\Thesis\\RES_CODE\\TEMP\\ag_xml_p.xml", "w+");
	fprintf(fp_xml_path, "</nodes>\n<edges>\n");
	
	fp_xml = fopen("F:\\PhD\\Thesis\\RES_CODE\\TEMP\\ag_xml.xml", "w+");
	
	//printf("\nGenerating the main basis line with length %d\n", total_nodes_rand); 
    // to generate a basis line
	mainline(total_nodes_rand);
	
	perct_30_of_total_nodes = (no_of_con+no_of_exp);
	perct_30_of_total_nodes = perct_30_of_total_nodes*3/10;
	perct_30_of_total_nodes_int = (int)perct_30_of_total_nodes;
	perct_30_of_total_nodes_rand = rand()%perct_30_of_total_nodes_int;
	
	perct_70_of_total_nodes = (no_of_con+no_of_exp);
	perct_70_of_total_nodes = perct_70_of_total_nodes*7/10;
	perct_70_of_total_nodes_int = (int)perct_70_of_total_nodes;	
	
	//printf("\nGenerating %d extra lines", perct_30_of_total_nodes_rand);
	
	for(i=0;i<perct_30_of_total_nodes_rand;i++)
	{
		bi_rand = rand()%2;
		if((bi_rand == 0) && (no_of_con_used<no_of_con))
			{
				perct_70_of_total_nodes_rand = rand()%perct_70_of_total_nodes_int;
				//printf("\n\nGenerating line with initial conditions with max length %d", perct_70_of_total_nodes_rand);
				initial(perct_70_of_total_nodes_rand);
			}
		else
			{
				perct_70_of_total_nodes_rand = rand()%perct_70_of_total_nodes_int;
				//printf("\n\nGenerating line from existing nodes and end at an existing one with max length %d", perct_70_of_total_nodes_rand);
				exist(perct_70_of_total_nodes_rand);
			}
	}
	
	// counting no of nodes actually used
	for(i=0; i<total_no_of_exp_or_con; i++)
	    {
	        if (condition[i].id != -1)
	            {
	                nodes++;
	            }
	        if (exploit[i].id != -1)
	            {
	                nodes++;                
	            }            
	    }
	met[loop_i].no_of_nodes = nodes;    
	
    for(i=0; i<no_of_con; i++)
    {
    	if(condition[i].id != -1)
    	{
    		//printf("\n\t%d\t\t-\t", condition[i].id);
			if(condition[i].initialgoal == 1)
			{
				//printf("Initial");
				fprintf(fp_dot_node, "C%d [xlabel = \"In\", fontname = \"sans bold\", shape = circle, fillcolor = khaki1, style = filled]\n",condition[i].id); // for storing graph in .dot format
				fprintf(fp_xml_node, "\t\t<condition id=\"%d\" type=\"Initial\">C%d</condition>\n",condition[i].id,condition[i].id); // for storing graph in .xml format
			}	        	
	        else if (condition[i].initialgoal == 9)
			{
				//printf("Goal");
				fprintf(fp_dot_node, "C%d [xlabel = \"Goal\", fontname = \"sans bold\", shape = circle, fillcolor = khaki1, style = filled]\n",condition[i].id); // for storing graph in .dot format
				fprintf(fp_xml_node, "\t\t<condition id=\"%d\" type=\"Goal\">C%d</condition>\n",condition[i].id,condition[i].id); // for storing graph in .xml format
			}	
	        else 
			{
				fprintf(fp_dot_node, "C%d [shape = circle, fontname = \"sans bold\", fillcolor = khaki1, style = filled]\n",condition[i].id); // for storing graph in .dot format;
	        	fprintf(fp_xml_node, "\t\t<condition id=\"%d\" type=\"NA\">C%d</condition>\n",condition[i].id,condition[i].id); // for storing graph in .xml format
	    	}
		}
    }         

    for(i=0; i<no_of_con; i++)
    {
    	if (condition[i].mark == 1)
    	{
	        for(j=0; j<total_no_of_nodes; j++)
		        {
		            condition[i].r = condition[i].r + g[j][condition[i].id][0];
		        }    		
		}
		
		if(condition[i].id != -1)
    	{
	    	//printf("\n\t%d\t\t-\t%d", condition[i].id, condition[i].r);
		}
    } 

    for(i=0; i<no_of_exp; i++)
    {
    	if(exploit[i].id != -1)
    	{
			//printf("\n\t%d\t-\t%0.1f", exploit[i].id, exploit[i].cvss);
			fprintf(fp_dot_node, "E%d [xlabel = %0.1f, fontname = \"sans bold\", shape = box, fillcolor = deepskyblue1, style = filled]\n",exploit[i].id,exploit[i].cvss); // for storing graph in .dot format
			fprintf(fp_xml_node, "\t\t<exploit id=\"%d\" cvss=\"%0.1f\">E%d</exploit>\n",exploit[i].id,exploit[i].cvss,exploit[i].id); // for storing graph in .xml format
		}
    }

    for(i=0; i<no_of_exp; i++)
    {
    	if (exploit[i].mark == 1)
    	{
	        for(j=0; j<total_no_of_nodes; j++)
	        {
	            exploit[i].r = exploit[i].r + g[j][exploit[i].id][0];
	        }
    	}
    	
    	if(exploit[i].id != -1)
    	{
        	//printf("\n\t%d\t-\t%d", exploit[i].id, exploit[i].r);  
		}
    } 		     

    for(i=0; i<no_of_exp; i++)
    {
    	if(exploit[i].mark == 1)
    	{
	        for(j=0; j<total_no_of_nodes; j++)
	        {
	        	for (k=0; k<total_no_of_exp_or_con; k++)
	        	{
	        		if((condition[k].id == j) && (condition[k].initialgoal == 1)) 
						{
							exploit[i].ri = exploit[i].ri + g[j][exploit[i].id][0];
							break;
						}					
				}
	        }
    	}
    	
    	if(exploit[i].id != -1)
    	{	    	
        	//printf("\n\t%d\t-\t%d", exploit[i].id, exploit[i].ri);
		}
    } 
    
    fprintf(fp_dot_path, "}");  // for storing graph in .dot format
    
    fclose(fp_dot_node);  // for storing graph in .dot format
    fclose(fp_dot_path);  // for storing graph in .dot format
    
    fprintf(fp_xml_path, "\t</edges>\n</AttackGraph>");  // for storing graph in .xml format    
    
    fclose(fp_xml_node);  // for storing graph in .xml format
    fclose(fp_xml_path);  // for storing graph in .xml format
    
    fp_dot_node = fopen("F:\\PhD\\Thesis\\RES_CODE\\TEMP\\ag_dot_n.dot", "r"); // to generate the graph in .dot format
    fp_dot_path = fopen("F:\\PhD\\Thesis\\RES_CODE\\TEMP\\ag_dot_p.dot", "r"); // to generate the graph in .dot format
    
    fp_xml_node = fopen("F:\\PhD\\Thesis\\RES_CODE\\TEMP\\ag_xml_n.xml", "r"); // to generate the graph in .xml format
    fp_xml_path = fopen("F:\\PhD\\Thesis\\RES_CODE\\TEMP\\ag_xml_p.xml", "r"); // to generate the graph in .xml format    
	    
    while((c = fgetc(fp_dot_node))!=EOF)
    	fprintf(fp_dot,"%c",c);

    while((c = fgetc(fp_xml_node))!=EOF)
    	fprintf(fp_xml,"%c",c);
 
    while((c = fgetc(fp_dot_path))!=EOF)
    	fprintf(fp_dot,"%c",c);
    	
    while((c = fgetc(fp_xml_path))!=EOF)
    	fprintf(fp_xml,"%c",c);    	
      
    fclose(fp_dot_node);  // for storing graph in .dot format
    fclose(fp_dot_path);  // for storing graph in .dot format
    fclose(fp_dot);
    
    fclose(fp_xml_node);  // for storing graph in .xml format
    fclose(fp_xml_path);  // for storing graph in .xml format
    fclose(fp_xml);
    
	return 1;
}
