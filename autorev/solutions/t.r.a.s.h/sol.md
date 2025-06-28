# ROP Chain Hash Solver - Writeup

This writeup covers both the `sample` and `auto` challenges, as they share the same fundamental structure with different ROP chains.

## Challenge Overview

The challenges consist of binaries that validate a 16-byte hash input using ROP (Return-Oriented Programming) chains. Each binary takes user input, checks if it's exactly 16 bytes, and then executes a ROP chain to validate the hash. If the validation succeeds, the program outputs "Yes"; otherwise, it outputs "No".

To understand what makes this challenge interesting, we need to understand what ROP chains are. Return-Oriented Programming uses small snippets of existing code (called "gadgets") that are chained together to perform complex computations. Each gadget typically ends with a `ret` instruction, which pops an address from the stack and jumps to it. By arranging addresses on the stack, you can control execution to jump from gadget to gadget.

In our challenge, the ROP chain implements hash validation logic like a custom virtual machine. Think of it as replacing traditional if-statements and comparisons with a sequence of small code snippets that load input bytes, perform arithmetic, and check conditions. For example, a validation like `input[0] + input[1] == 150` becomes a chain of gadgets that load both bytes, add them together, compare the result to 150, and set flags based on the outcome.


## Binary Analysis and Discovery

### Initial Static Analysis

Using decompilation tools like [dogbolt.org](https://dogbolt.org), I analyzed the binary structure and discovered the key components:

```c
__int64 sub_11E9() {
    char *v1; // rbx
    unsigned int v2; // eax
    // ... variable declarations ...

    v6 = getline(&lineptr, &n, stdin);
    if (v6 >= 0 && (v1 = lineptr, v1[strcspn(lineptr, "\n")] = 0, v6 = strlen(lineptr), v6 == 16)) {
        sub_131A();  // This is where the magic happens
        v3 = v2;
        free(lineptr);
        return v3;
    } else {
        free(lineptr);
        return 0;
    }
}

__int64 __fastcall main(__int64 a1, char **a2, char **a3) {
    if ((unsigned int)sub_11E9() == 1) {
        puts("Yes");
        return 0;
    } else {
        puts("No");
        return 1;
    }
}

void sub_131A() {
    ; // Empty in decompiled view - this is suspicious!
}
```

The program flow is straightforward: read exactly 16 bytes of input, call `sub_131A()` to validate it, and print "Yes" or "No" based on the result. The mystery lies in function `sub_131A()`, which appears empty in decompilers but must contain the validation logic.

### Discovering the Stack Pivot

Examining the assembly code of function `0x131a` revealed the true nature of the validation:

```assembly
131a: 48 8d 1d ef 2c 00 00    leaq   11503(%rip), %rbx    # 0x4010
1321: 48 87 e3                xchgq  %rbx, %rsp
1324: c3                      retq
```

This function performs a **stack pivot operation**:

1. `leaq 11503(%rip), %rbx` - Load the address 0x4010 into RBX register
2. `xchgq %rbx, %rsp` - Swap RBX and RSP (stack pointer)
3. `retq` - Return, but now the stack pointer points to 0x4010

### Understanding the Stack Pivot Mechanism

The stack pivot is a clever technique that redirects program execution. Here's what happens:

**Before the pivot:**
- RSP points to the normal function call stack
- The `ret` instruction would return to the calling function

**After the pivot:**
- RSP now points to address 0x4010 in the data section
- The `ret` instruction pops the value at 0x4010 and jumps to it
- This value is the address of the first ROP gadget

This technique bypasses normal function call conventions and transfers control to a custom ROP chain stored in the binary's data section.

## Understanding the Dual Stack Architecture
What makes this ROP chain particularly sophisticated is that it doesn't just perform a simple stack pivot once. Examining the individual gadgets reveals they each implement their own stack swapping mechanism. Each gadget follows a consistent pattern: it starts with `xchgq %rbx, %rsp` to swap from the ROP chain stack to a working stack, performs its calculations using normal stack-based operations, then ends with another `xchgq %rbx, %rsp` to swap back to the ROP chain stack before returning.
This dual-stack architecture serves a crucial purpose. The ROP chain stack at 0x4010 contains the sequence of gadget addresses that control execution flow, but gadgets need actual stack space to perform calculations, store temporary values, and manipulate data. By swapping to a separate working stack area, each gadget gets access to a clean workspace for its operations without corrupting the carefully arranged sequence of return addresses that drives the chain forward.
This is why our symbolic execution setup must provide two distinct stack areas: the ROP chain data at 0x4010 for controlling gadget sequencing, and a realistic working stack space where gadgets can perform their actual computational work. Without understanding this architecture, attempts to execute the ROP chain would fail as gadgets tried to use non-existent or corrupted stack space for their operations.


### Analyzing the ROP Chain Data

Examining the data at address 0x4010 reveals a sequence of addresses:

```
4010: 44160000 00000000    # 0x0000000000001644 - Address of first gadget
4018: 46140000 00000000    # 0x0000000000001446 - Address of second gadget  
4020: 16170000 00000000    # 0x0000000000001716 - Address of third gadget
4028: 00140000 00000000    # 0x0000000000001400 - Address of fourth gadget
...
```

Each 8-byte entry is the address of a ROP gadget. When the first gadget finishes executing and hits its `ret` instruction, it pops the next address (0x1446) from the stack and jumps to it, continuing the chain.

## Failed Approaches and Lessons Learned

### Attempt 1: Traditional Angr Analysis

My first approach was to use angr in the conventional way - start from the binary's entry point and search for execution paths that result in printing "Yes":

```python
# Simple approach that doesn't work well
project = angr.Project('./sample')
state = project.factory.entry_state()
simgr = project.factory.simulation_manager(state)
simgr.explore(find=lambda s: b"Yes" in s.posix.dumps(1))
```

**Problems encountered:**
- Angr found solutions, but they were incorrect (often strings of spaces)
- The solutions didn't actually validate when tested against the real binary
- The complex stack pivoting confused angr's analysis -> or i  don't know how to force it.  
- Performance was poor due to exploring many irrelevant execution paths

**Root cause:** The stack pivot operation creates a discontinuity in the normal execution flow that angr's default exploration strategies don't handle well -> or i  don't know how to force it. In  my case:  By the time angr reaches the "Yes" output, it has lost track of the precise constraints that the ROP chain imposed.

### Attempt 2: Manual ROP Analysis

I considered manually analyzing each ROP gadget to understand the validation constraints:

**Problems with this approach:**
- Time-intensive reverse engineering for each gadget
- Error-prone manual constraint transcription
- Not scalable to 100+ different ROP chains
- Easy to miss subtle inter-gadget dependencies

**Why this wouldn't scale:** Each challenge binary contains a different ROP chain with different validation logic. Manually analyzing 100+ chains would be impractical for a CTF environment.

### The Key Insight: Direct ROP Chain Analysis

The breakthrough came from realizing that I could bypass the entire program setup and execute just the ROP chain portion with symbolic inputs. This approach offers several advantages:

1. **Focused Analysis**: Only analyze the validation logic, not the entire program
2. **Precise State Control**: Set up the exact processor state needed for ROP execution
3. **Constraint Capture**: Let angr automatically discover constraints through symbolic execution
4. **Scalable Automation**: Same approach works for all similar challenges

## Solution Architecture

### Phase 1: Understanding ROP Chain Requirements

To execute a ROP chain successfully, several conditions must be met. Understanding these requirements comes from careful analysis of how the original program established its execution environment before the stack pivot occurred.

**Register State:**
- **RSP (Stack Pointer)**: Must point to the ROP chain data (0x4010)
- **RBP (Base Pointer)**: Provides workspace for gadget operations and maintains the original stack frame context
- **RBX**: Initially holds a marker value, but becomes part of the dual-stack mechanism during gadget execution
- **Other registers**: Set to reasonable values to avoid crashes during gadget execution

**Critical Insight About Input Access:**
Unlike what we might initially assume, the ROP chain does not rely on the RDI register to access input data. Instead, it uses the original program's calling convention and stack layout. The input pointer was placed on the stack as part of the normal function call sequence before the stack pivot occurred. The ROP gadgets access this input data by loading the pointer from its expected location in the stack frame, then dereferencing it to reach the actual input bytes. This explains why we can set RDI to any reasonable value during our setup - the gadgets will ignore it and use their own stack-based addressing to find the input data.

**Memory Layout:**
- **Input Data**: 16-byte symbolic input stored at the location expected by the original program's memory layout
- **Dual Stack Areas**: Both ROP chain stack (for gadget addresses) and working stack (for calculations)
- **Stack Frame Context**: Preserved memory layout that allows gadgets to find the input pointer through normal stack operat

### Phase 2: Symbolic Execution Setup

The solution creates a carefully crafted execution environment that simulates the exact moment when the ROP chain begins:

```python
def setup_project_and_state(binary_path):
    """
    Initialize project and create symbolic execution state for ROP chain analysis
    
    This function sets up the foundational environment that angr needs to symbolically
    execute the ROP chain. Think of it as preparing a controlled laboratory where we
    can observe how the ROP gadgets interact with our symbolic input through their
    actual stack-based access mechanisms.
    """
    # Load the binary with PIE disabled (base_addr=0) to use direct offsets
    # This matches the requirement that PIE is disabled for direct addressing
    project = angr.Project(binary_path, main_opts={"base_addr": 0}, auto_load_libs=False)
    
    # These addresses are consistent across all challenge binaries
    start_addr = 0x1324      # Where ROP chain execution begins (after stack pivot)
    rop_chain_addr = 0x4010  # Location of ROP chain data in .data section
    input_addr = 0x5000      # Where we'll store our symbolic 16-byte input
    
    # Create a blank state starting at the ROP chain entry point
    # This bypasses all the normal program startup and gets us straight to the interesting part
    state = project.factory.blank_state(addr=start_addr)
    
    # Point the stack pointer to the beginning of our ROP chain
    # This is crucial because the ROP gadgets expect to find their next targets on the stack
    state.regs.rsp = rop_chain_addr
    
    # Create our symbolic input - this represents the 16-byte hash we're trying to discover
    # Each byte is completely unconstrained initially, giving the solver maximum flexibility
    symbolic_input = claripy.BVS('hash_input', 16 * 8)  # 16 bytes * 8 bits per byte
    
    # Apply ASCII constraints to each byte of our input
    # This ensures we get printable characters rather than arbitrary binary data
    for i in range(16):
        byte_val = symbolic_input.get_byte(i)
        state.solver.add(byte_val >= 32)   # Space character (minimum printable)
        state.solver.add(byte_val <= 126)  # Tilde character (maximum printable)
    
    # Store our symbolic input in memory where the ROP chain can access it
    # The key insight: ROP gadgets access input through the original program's memory layout,
    # not through registers like RDI. They load a pointer from the stack frame and dereference it.
    state.memory.store(input_addr, symbolic_input)
    
    # Set up the execution environment to match what the ROP chain expects
    realistic_stack_base = 0x7ffe00000000  # Typical user-space stack location for workspace
    state.regs.rbp = realistic_stack_base   # Base pointer - some gadgets use RBP-relative addressing
    state.regs.rbx = 0x00000000deadbeef     # Distinctive marker for debugging purposes -> did I reached the end of the ROP chain
    
    # Note about RDI: While we could set this to point to our input, analysis shows that
    # the ROP gadgets don't actually use RDI to access input data. Instead, they use
    # stack-based addressing to load the input pointer from the original function's
    # stack frame, then dereference it. We can set RDI to any reasonable value.
    state.regs.rdi = input_addr             # Set for completeness, but likely unused by gadgets
    
    # Critical insight: Each ROP gadget actually pivots back and forth between two stacks
    # Looking at the assembly, gadgets start with `xchgq %rbx, %rsp` (swap to working stack),
    # perform their calculations using normal stack operations, then end with `xchgq %rbx, %rsp` 
    # (swap back to ROP chain stack). This means we need TWO functional stack areas:
    # 1. ROP chain stack (RSP=0x4010) - contains gadget addresses
    # 2. Working stack (RBX initially) - provides space for gadget calculations and storage
    # The realistic_stack_base provides the working stack space that gadgets actually use
    
    return project, state, symbolic_input, input_addr
```

### Understanding the State Setup Rationale

Each register and memory setup serves a specific purpose:

**Start Address (0x1324):** This is the address immediately after the stack pivot operation. Starting here means we skip the pivot itself but begin with the stack already pointing to the ROP chain.

**Stack Pointer (0x4010):** Points to the first gadget address in the ROP chain. When the first `ret` instruction executes, it will pop this address and jump to the first gadget.

**Input Address (0x5000):** A safe memory location where we store our symbolic input. This address is chosen to avoid conflicts with existing program data.

**Base Pointer (0x7ffe00000000):** Provides a realistic stack base address. Some gadgets might use RBP-relative addressing for temporary storage, so this needs to point to valid, writable memory space.

**RDI Register:** The x86-64 calling convention uses RDI for the first function argument. Since the original program passes the input buffer to the validation function, RDI should point to our input data.

**RBX as Completion Marker:** Set to a distinctive value that helps with debugging. Some gadgets might use or modify RBX, and this value helps identify when execution has gone off track.

### Phase 3: Constraint Accumulation Through Symbolic Execution

The core of the solution lies in how symbolic execution automatically discovers and accumulates constraints as the ROP chain executes:

```python
def solve_rop_chain(project, state, symbolic_input, max_steps=90):
    """
    Execute ROP chain symbolically using unconstrained state detection

    This is the heart of our solving approach. We let angr step through each
    ROP gadget, building up mathematical constraints that represent the hash
    validation logic. When the chain reaches its end (becomes unconstrained),
    we know we've captured all the validation requirements.
    """
    # Create a simulation manager to control symbolic execution
    simgr = project.factory.simulation_manager(state)
    step_count = 0

    # Step through the ROP chain gadget by gadget
    while simgr.active and step_count < max_steps:
        # Execute one step (typically one ROP gadget)
        simgr.step()
        step_count += 1

        # Check for unconstrained state (ROP chain completion)
        if simgr.unconstrained:
            return extract_solution_from_unconstrained(simgr, symbolic_input)

    return None
```

### Understanding Constraint Accumulation

As each ROP gadget executes, it performs operations on our symbolic input and adds constraints to the solver. Here's how different types of operations create constraints:

**Loading Operations:**
```assembly
mov rax, [rdi+5]    ; Load input[5] into RAX
```
Creates symbolic expression: `rax = symbolic_input[5]`

**Arithmetic Operations:**
```assembly
add rax, rdx        ; Add two values
```
If RAX contains `symbolic_input[5]` and RDX contains `symbolic_input[3]`, this creates: `result = symbolic_input[5] + symbolic_input[3]`

**Comparison Operations:**
```assembly
cmp rax, 0x42       ; Compare with 0x42
jne failure         ; Jump if not equal
```
If execution continues past this point, it creates constraint: `symbolic_input[5] + symbolic_input[3] == 0x42`

**Flag-based Logic:**
Many gadgets use processor flags to implement conditional logic. If a gadget sets flags based on a comparison and another gadget branches based on those flags, the symbolic execution engine automatically tracks these dependencies.

### The Unconstrained State Breakthrough

The most crucial insight in this solution is understanding what happens when a ROP chain completes:

**Normal ROP Execution:**
1. Gadget executes and hits `ret` instruction
2. `ret` pops next address from stack and jumps to it
3. Next gadget executes, cycle repeats

**Chain Completion:**
1. Final gadget executes and hits `ret` instruction  
2. `ret` pops an address that is either:
   - Invalid (causes segmentation fault)
   - Symbolic (depends on input data)
   - Points to uninitialized memory
3. Angr cannot determine where to continue execution
4. State becomes "unconstrained"

### Why Unconstrained States Are Perfect for Our Solution

When a state becomes unconstrained, it means angr has lost track of concrete execution flow, but **all the constraints accumulated during the ROP chain execution are preserved**. This creates the perfect opportunity to add our success condition:

```python
def extract_solution_from_unconstrained(simgr, symbolic_input, max_attempts=3):
    """
    Extract and validate solution from unconstrained state with retry logic

    This function implements our key insight: we can add the success constraint
    (EAX == 1) after the ROP chain completes, then ask the solver to find an
    input that satisfies both the accumulated validation constraints AND
    produces the required successful result.
    """
    if not simgr.unconstrained:
        return None

    state = simgr.unconstrained[0]

    # Add the critical success constraint: the accumulated result must equal 1
    # This is like saying "given all the hash validation math we discovered,
    # find me an input where the final result indicates success"
    state.solver.add(state.regs.eax == 1)

    # Try multiple times to get a valid, usable solution
    for attempt in range(max_attempts):
        if not state.solver.satisfiable():
            return None

        try:
            # Ask the constraint solver for a solution
            solution_bytes = state.solver.eval(symbolic_input, cast_to=bytes)
            formatted_solution = format_solution(solution_bytes)

            # Check if this solution passes our quality validation
            if formatted_solution['valid']:
                return formatted_solution
            else:
                # If the solution is invalid, exclude it and try again
                exclusion_constraint = symbolic_input != solution_bytes
                state.solver.add(exclusion_constraint)

        except Exception as e:
            return None

    return None
```

### Why This Approach Works

The power of this approach lies in the separation of concerns:

1. **Constraint Discovery**: The ROP chain execution automatically discovers all validation constraints without manual analysis
2. **Success Condition**: We add the success condition (`EAX == 1`) only after capturing all validation logic
3. **Solver Power**: Modern constraint solvers can efficiently find inputs satisfying complex mathematical relationships
4. **Automation**: The same code works for any ROP chain that follows this pattern

## Automation and Batch Processing

### Challenge Variation Understanding

The challenge set consists of 100+ similar binaries with identical structure but different ROP chains. Understanding what varies and what remains constant is crucial for automation:

**Constant Elements:**
- Binary layout and entry points
- Stack pivot mechanism and location (0x131a)  
- ROP chain storage location (0x4010)
- Input validation (exactly 16 bytes)
- Success condition (return value 1)

**Variable Elements:**
- ROP gadget addresses and sequence
- Specific validation constraints
- Mathematical relationships between input bytes
- The actual hash value that satisfies validation

This consistency enables a single solution approach to work across all challenges - only the ROP chain data at 0x4010 changes, but the execution framework remains identical.

## Development Methodology and Learning Process

### The Journey to Understanding

The path to this solution involved significant experimentation and learning about both ROP chains and symbolic execution:

**Initial Overcomplication:** I initially tried to manually detect when the ROP chain completed by looking for specific patterns or gadgets. This approach was complex and brittle.

**The Breakthrough Realization:** The key insight came when I realized that angr naturally detects ROP completion through unconstrained states. Instead of fighting this behavior, I could leverage it as a feature.

**Research Challenges:** Limited online resources existed for combining angr with ROP chain analysis. Most angr tutorials focus on traditional binary exploitation or simple constraint solving, not complex ROP-based validation systems.

### Iterative Development Approach

The solution evolved through several iterations:

**Phase 1 - Learning Script Creation:** I developed `learn.py` as an interactive tutorial to understand angr's behavior:
```python
# Interactive exploration of angr concepts
import IPython
project = angr.Project('./sample')
state = project.factory.blank_state(addr=0x1324)
# ... step-by-step state setup and testing
IPython.embed()  # Drop into interactive shell for experimentation
```

**Phase 2 - State Understanding:** Focused on reproducing the exact processor state that the ROP chain expects, including memory layout, register values, and stack configuration.

**Phase 3 - Constraint Analysis:** Used extensive logging to understand how constraints accumulate during symbolic execution and how different gadget types contribute to the overall constraint system.

**Phase 4 - Automation:** Generalized the approach to work across multiple challenge binaries and added robust error handling and validation.

## Conclusion

This solution successfully automated the solving of ROP-based hash validation challenges by leveraging several key insights:

**Technical Innovation:** Using unconstrained state detection as a natural termination point for ROP chain analysis eliminated the need for manual chain completion detection.

**Symbolic Execution Power:** Demonstrating how symbolic execution can automatically discover complex mathematical constraints embedded in ROP chains without manual reverse engineering.

**Automation Success:** Creating a robust, scalable solution that works across 100+ similar challenges with minimal manual intervention.


The approach transforms what could be a time-intensive manual reverse engineering task into an automated constraint solving problem, showcasing the power of modern program analysis techniques for CTF challenges. The solution successfully balances technical sophistication with practical usability, making it an effective tool for tackling large-scale ROP-based challenges.