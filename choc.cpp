#include <iostream>
using namespace std;

int binary(int b[],int x,int ind,int n,int lo,int hi){
	int mid=(lo+hi)/2;
	if (b[mid]-b[ind-1]-x>=x and b[n]-b[mid-1]>=b[mid]-b[ind-1]-x and b[mid-1]-b[ind-1]-x<x){
		return  mid;
	}
	else if (b[mid]-b[ind-1]-x<x){
		return (b,x,ind,n,mid+1,hi);
	}
	else if (b[mid]-b[ind-1]-x>x)
}

int main() 
{
	// your code goes here
	ios::sync_with_stdio(false);
	int t;
	cin >> t;
	while (t--)
	{
	    int n;
	    cin >> n;
	    int a[n+1]={0};
	    int b[n+1]={0};
	    for (int i=1; i<=n; i++){
	    	cin >> a[i];
	    	b[i]=a[i]+b[i-1];
	    }
	    int ans=a[1];
	    while (1){

	    }
	}
	return 0;
}
