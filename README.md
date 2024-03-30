# NetFC
An unofficial implementation of NetFC(data plane float ploint operations +,-,*,/)  in BMV2 with $P4_{16}$.
My simulation is based on '[p4run](https://github.com/nsg-ethz/p4-utils)' which is an improved version of mininet and p4c to easy P4 simulations.




Details reference to "[NetFC: Enabling Accurate Floating-point Arithmetic on Programmable Switches](https://arxiv.org/pdf/2106.05467)". 
Code is based on [the official Repo](https://github.com/frankucas/NetFC.git). Many thanks to them. 


## How to run
The simulaiton topology: h1--s1--h2
```
  sudo python run_XXX.py
  mininet>
```

in another terminal:
```
sudo python get_digest.py
```
return to the first terminal:
```
mininet> h1 python sender.py
```
This will start sending packets from h1 to h2 via s1. 
  


## Note
There may be some bugs because I am a bad programmer. If there are, contact me. 
If there is a license issue, please contact me, I may delete this repo.

## Lisence:

MIT License

Copyright (c) [year] [fullname]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
