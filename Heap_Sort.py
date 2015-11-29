#!/usr/bin/python
import math
A=[1,4,2,6,9,10,5]
heap_size=len(A)
def max_heapify(A,i):
	l=(2*i)+1
	r=2*(i+1)
	if l<=heap_size and A[l]>A[i]:
		largest=l
	else:
		largest=i
	if r<=heap_size and A[r]>A[largest]:
		largest=r
	if largest!=i:
		t=A[i]
		A[i]=A[largest]
		A[largest]=t
		max_heapify(A,largest)
def build_max_heap(A):
	heap_size=len(A)
	for i in range(int(math.floor(heap_size/2)))[::-1]:
		max_heapify(A,i)
def heap_sort(A):
	build_max_heap(A)
	print A
	for i in range(len(A))[::-1]:
		global heap_size
		heap_size-=1
		max_heapify(A,1)
if __name__=='__main__':
	print A
	heap_sort(A)
	print A
	
