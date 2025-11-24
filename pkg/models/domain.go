package models

//DOmain tracks discovery sources for recursion
type Domain struct{
	Name string
	Source string  //"certstream" , "brute", "recursion"
	Found [] string  //IPs found
}