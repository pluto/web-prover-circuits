# JSON Notes

Okay what we can do is have a hash chain up the stack and store at most MAX_STACK_HEIGHT hash values, then write to this array at the current depth for each new value we get. We also should hash the stack indicator (array vs. object).

We then just have to assert that we get an `ArrayEqual` with our given input at some point. We also assert the hash of the value itself is correct (possibly this just happens in a uniform way thinking of it as an object itself? Some details remain.)