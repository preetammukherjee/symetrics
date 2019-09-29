set terminal svg
set title "Metrics on Attack Graph" font "Times:Bold, 20"
set auto x
set style data histogram
set style histogram cluster gap 1
set style fill solid border -1
set boxwidth 0.9
plot 'F:\PhD\Thesis\RES_CODE\TEMP\met_nodes.dat' using 2:xtic(1) ti col, '' u 3 ti col, '' u 4 ti col, '' u 5 ti col