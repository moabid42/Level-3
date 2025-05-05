eval((lambda x: (_ for _ in ()).throw(AssertionError) if len(x) > 42 else x)(input(">>> ").strip()), {'__builtins__': {'print': print}})
