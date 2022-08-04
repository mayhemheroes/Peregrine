//TODO: Add support for variable shadowing of the same name/type in different scopes

#include "typeChecker.hpp"
#include "ast/ast.hpp"
#include "ast/types.hpp"

#include <cassert>
#include <iostream>
#include <memory>
namespace TypeCheck{

TypeChecker::TypeChecker(ast::AstNodePtr ast) {
    m_env = createEnv(nullptr);
    m_currentFunction = nullptr;
    ast->accept(*this);
    if(m_errors.size()!=0) {
        for(auto& err : m_errors) {
            display(err);
        }
        exit(1);
    }
}
bool TypeChecker::defined(ast::AstNodePtr name){
    bool defined_before=true;
    
    {
        if(name->type()==ast::KAstIdentifier){
            auto identifierType = m_env->get(identifierName(name));
            if (identifierType==std::nullopt) {
                defined_before=false;
            }
        }
    }
    return defined_before;
}
void TypeChecker::add_error(Token tok, std::string_view msg) {
    PEError err = {
        {tok.line, tok.start, tok.location, m_filename, tok.statement},
        std::string(msg),
        "TypeError",
        "",
        ""};
    m_errors.push_back(err);
    
}

EnvPtr TypeChecker::createEnv(EnvPtr parent) {
    return std::make_shared<SymbolTable<TypePtr>>(parent);
}

void TypeChecker::checkBody(ast::AstNodePtr body,
                            std::vector<std::pair<TypePtr,ast::AstNodePtr>> add_var) {
    EnvPtr previousEnv = m_env;
    m_env = createEnv(previousEnv);
    if(add_var.size()!=0) {
        for(auto& var : add_var) {
            m_env->set(var.second,var.first);
        }
    }
    body->accept(*this);
    m_env = previousEnv;
}

void TypeChecker::check(ast::AstNodePtr expr, const TypePtr expTypePtr) {
    if(expTypePtr==NULL){
        return;
    }
    expr->accept(*this);
    if(m_result==NULL){
        return;
    }
    const Type& exprType = *m_result;

    if (exprType != *expTypePtr) {
        if (!exprType.isConvertibleTo(*expTypePtr) &&
            !expTypePtr->isConvertibleTo(exprType)) {
            add_error(expr->token(), "expected type " + expTypePtr->stringify() +
                                     ", got " + exprType.stringify() +
                                     " instead");
        }

        // TODO: convert one type to another
    }
}

std::string TypeChecker::identifierName(ast::AstNodePtr identifier) {
    assert(identifier->type() == ast::KAstIdentifier);

    return std::dynamic_pointer_cast<ast::IdentifierExpression>(identifier)
        ->value();
}

bool TypeChecker::visit(const ast::ClassDefinition& node) { return true; }

bool TypeChecker::visit(const ast::ImportStatement& node) { return true; }

// TODO: default args
bool TypeChecker::visit(const ast::FunctionDefinition& node) {
    EnvPtr oldEnv = m_env;
    m_env = createEnv(oldEnv);

    std::vector<TypePtr> parameterTypes;
    parameterTypes.reserve(node.parameters().size());

    for (auto& param : node.parameters()) {
        if (param.p_default->type() != ast::KAstNoLiteral) {
            if (param.p_type->type() != ast::KAstNoLiteral) {
                param.p_type->accept(*this);
                check(param.p_default, m_result);
            }

            param.p_default->accept(*this);
            parameterTypes.push_back(m_result);
            m_env->set(identifierName(param.p_name), m_result);
            continue;
        }

        param.p_type->accept(*this);
        parameterTypes.push_back(m_result);
        m_env->set(identifierName(param.p_name), m_result);
    }
    node.returnType()->accept(*this);
    auto returnType=m_result;
    auto functionType =
        std::make_shared<FunctionType>(parameterTypes, returnType);

    auto oldFunction = m_currentFunction;
    auto oldReturnType = m_returnType;
    m_returnType = NULL;
    m_currentFunction = functionType;
    node.body()->accept(*this);
    if(m_returnType!=NULL){
        auto& nonconstnode = const_cast<ast::FunctionDefinition&>(node);
        nonconstnode.setType(m_returnType);
        functionType =std::make_shared<FunctionType>(parameterTypes, m_returnType);
    }
    m_returnType = oldReturnType;
    m_currentFunction = oldFunction;

    m_env = oldEnv;

    m_env->set(identifierName(node.name()), functionType);
    return true;
}

bool TypeChecker::visit(const ast::VariableStatement& node) {
    //TODO:check if redefination
    auto& nonConstNode = const_cast<ast::VariableStatement&>(node);
    if(node.name()->type()==ast::KAstIdentifier){
        node.varType()->accept(*this);
        TypePtr varType = m_result;
        bool defined_before=defined(node.name());
        if (varType->category() == TypeCategory::Void) {
            // inferring the type of the variable
            node.value()->accept(*this);
            if(m_result->category()==MultipleReturn){
                add_error(node.token(), "Too few variables on the left hand side");
                return true;
            }
            else if(m_result->category()==Void){
                add_error(node.token(), "You cant declare a variable of type void");
                return true;
            }
            nonConstNode.setProcessedType(m_result,defined_before);
            varType = m_result;
        } else{
            if(node.value()->type()!=ast::KAstNoLiteral){
                check(node.value(), varType);
            }
            if(m_result->category()==MultipleReturn){
                add_error(node.token(), "Too few variables on the left hand side");
                return true;
            }
            else if(m_result->category()==Void){
                add_error(node.token(), "You cant declare a variable of type void");
                return true;
            }
            nonConstNode.setProcessedType(varType,true);
        }
        m_env->set(identifierName(node.name()), varType);
    }
    else{
        node.name()->accept(*this);
        check(node.value(), m_result);
    }
    return true;
}

bool TypeChecker::visit(const ast::ConstDeclaration& node) {
    //TODO:check if redefination
    auto& nonConstNode = const_cast<ast::ConstDeclaration&>(node);

    node.constType()->accept(*this);
    TypePtr constType = m_result;

    if (constType->category() == TypeCategory::Void) {
        // inferring the type of the constant
        node.value()->accept(*this);
        if(m_result->category()==MultipleReturn){
            add_error(node.token(), "Too few variables on the left hand side");
            return true;
        }
        else if(m_result->category()==Void){
            add_error(node.token(), "You cant declare a constant of type void");
            return true;
        }
        nonConstNode.setProcessedType(m_result);
        constType = m_result;
    } else{
        check(node.value(), constType);
        if(m_result->category()==MultipleReturn){
            add_error(node.token(), "Too few variables on the left hand side");
            return true;
        }
        else if(m_result->category()==Void){
            add_error(node.token(), "You cant declare a variable of type void");
            return true;
        }
        nonConstNode.setProcessedType(NULL);
    }

    m_env->set(identifierName(node.name()), constType);
    return true;
}

bool TypeChecker::visit(const ast::TypeDefinition& node) {
    node.baseType()->accept(*this);
    TypePtr userDefinedType = std::make_shared<UserDefinedType>(m_result);

    m_env->set(identifierName(node.name()), userDefinedType);
    return true;
}

bool TypeChecker::visit(const ast::IfStatement& node) {
    check(node.condition(), TypeProducer::boolean());
    checkBody(node.ifBody());

    for (auto& elif : node.elifs()) {
        check(elif.first, TypeProducer::boolean());
        checkBody(elif.second);
    }

    if (node.elseBody()->type() != ast::KAstNoLiteral){
        checkBody(node.elseBody());
    }
    return true;
}

bool TypeChecker::visit(const ast::AssertStatement& node) { 
    check(node.condition(), TypeProducer::boolean());
    return true; 
}

bool TypeChecker::visit(const ast::StaticStatement& node) { return true; }

bool TypeChecker::visit(const ast::ExportStatement& node) { 
    node.body()->accept(*this); 
    return true; 
}

bool TypeChecker::visit(const ast::InlineStatement& node) {
    node.body()->accept(*this); 
    return true; 
}

bool TypeChecker::visit(const ast::RaiseStatement& node) { 
    //TODO: Check if the exception is a subclass of the exception in the except block
    node.value()->accept(*this);
    return true; 
}

bool TypeChecker::visit(const ast::WhileStatement& node) {
    check(node.condition(), TypeProducer::boolean());
    checkBody(node.body());
    return true;
}

bool TypeChecker::visit(const ast::ForStatement& node) {
    // check(node.sequence(), *TypeProducer::list());
    EnvPtr oldEnv = m_env;
    m_env = createEnv(oldEnv);
    // m_env->set(identifierName(node.variable()), m_result); // result may not
    // be correct here

    node.body()->accept(*this);
    return true;
}

bool TypeChecker::visit(const ast::MatchStatement& node) { 
    std::vector<TypePtr> types;
    auto match_item=node.matchItem();
    for(auto& item:match_item){
        item->accept(*this);
        types.push_back(m_result);
    }
    auto cases=node.caseBody();
    for(auto& case_item:cases){
        checkBody(case_item.second);
        auto case_exp=case_item.first;
        for(size_t i=0;i<types.size();i++){
            if(i>(case_exp.size()-1)){
                //The last item is _. This has being checked in the parser
                break;
            }
            else if(case_exp[i]->type()!=ast::KAstNoLiteral){
                check(case_exp[i],types[i]);
            }
        }
    }
    return true; 
}

bool TypeChecker::visit(const ast::ScopeStatement& node) {
    checkBody(node.body());
    return true;
}

bool TypeChecker::visit(const ast::ReturnStatement& node) {
    if (!m_currentFunction) {
        add_error(node.token(), "can not use return outside of a function");
    }

    node.returnValue()->accept(*this);
    if(m_currentFunction->returnType()->category()==TypeCategory::Void){
        m_returnType=m_result;
    }
    else{
        check(node.returnValue(), m_currentFunction->returnType());
    }
    return true;
}

bool TypeChecker::visit(const ast::DecoratorStatement& node) { return true; }

bool TypeChecker::visit(const ast::ListLiteral& node) {
    //TODO: If the variable is empty do something for the variable
    //val=[]
    //Infer it properly
    if(node.elements().size() == 0) {
        // m_result = TypeProducer::list();
        return true;
    }
    node.elements()[0]->accept(*this); // TODO: check to see if its not empty
    TypePtr listType = m_result;

    for (auto& elem : node.elements()) {
        check(elem, listType);
    }
    m_result = TypeProducer::list(listType, std::to_string(node.elements().size()));
    return true;
}

bool TypeChecker::visit(const ast::DictLiteral& node) { return true; }

bool TypeChecker::visit(const ast::ListOrDictAccess& node) { return true; }

bool TypeChecker::visit(const ast::BinaryOperation& node) {
    node.left()->accept(*this);
    TypePtr leftType = m_result;
    node.right()->accept(*this);
    if(m_result==NULL||leftType==NULL){
        m_result=NULL;//If left or right is null, the result is null
        return true;
    }
    TypePtr result = leftType->infixOperatorResult(node.op(), m_result);

    if (!result) {
        add_error(node.token(),
              "operator " + node.op().keyword + " can not be used with types " +
                  leftType->stringify() + " and " + m_result->stringify());
    }

    m_result = result;
    return true;
}

bool TypeChecker::visit(const ast::PrefixExpression& node) {
    node.right()->accept(*this);
    TypePtr result = m_result->prefixOperatorResult(node.prefix());

    if (!result) {
        add_error(node.token(), "operator " + node.prefix().keyword +
                                " can not be used with type " +
                                m_result->stringify());
    }

    m_result = result;
    return true;
}

bool TypeChecker::visit(const ast::PostfixExpression& node) { 
    node.left()->accept(*this);
    TypePtr result = m_result->postfixOperatorResult(node.postfix());

    if (!result) {
        add_error(node.token(), "operator " + node.postfix().keyword +
                                " can not be used with type " +
                                m_result->stringify());
    }

    m_result = result;
    return true; 
}

bool TypeChecker::visit(const ast::FunctionCall& node) {
    node.name()->accept(*this);

    if (m_result->category() != TypeCategory::Function)
        add_error(node.token(), identifierName(node.name()) + " is not a function");

    auto functionType = std::dynamic_pointer_cast<FunctionType>(m_result);

    if (functionType->parameterTypes().size() != node.arguments().size())
        add_error(node.token(), "invalid number of arguments passed to " +
                                identifierName(node.name()));

    for (size_t i = 0; i < node.arguments().size(); i++) {
        check(node.arguments()[i], functionType->parameterTypes()[i]);
    }

    m_result = functionType->returnType();
    return true;
}

bool TypeChecker::visit(const ast::DotExpression& node) {
    if(node.owner()->type()==ast::KAstIdentifier&&node.referenced()->type()==ast::KAstIdentifier){
        auto name=identifierName(node.owner());
        auto ref=identifierName(node.referenced());
        auto enum_map=m_env->getEnumMap();
        if(enum_map.contains(name)){
            auto type=enum_map[name];
            auto _enum=std::dynamic_pointer_cast<types::EnumType>(type);
            auto items=_enum->getItem();
            if(std::count(items.begin(),items.end(),ref)){
                m_result=type;
            }
            else{
                add_error(node.token(),ref+" is not a member of "+name);
                m_result=NULL;
            }
            return true; 
        }
    }
    node.owner()->accept(*this);
    auto type=m_result;
    if(type==NULL){
        return true;
    }
    switch(type->category()){
        case TypeCategory::Union:{
            auto union_type=std::dynamic_pointer_cast<types::UnionTypeDef>(type);
            auto items=union_type->getItem();
            m_result=NULL;
            if(node.referenced()->type()!=ast::KAstIdentifier){
                add_error(node.token(),"Union member must be an identifier");
            }
            else if(items.contains(identifierName(node.referenced()))){
                m_result=items[identifierName(node.referenced())];
            }
            else{
                add_error(node.token(),identifierName(node.referenced())+" is not a member of "+type->stringify());
            }
            break;            
        }
        default:{
            add_error(node.token(),"can not access member of "+type->stringify());
            m_result=NULL;
            return true;
        }
    }
    return true; 
}

bool TypeChecker::visit(const ast::ArrowExpression& node) { return true; }

bool TypeChecker::visit(const ast::IdentifierExpression& node) {
    auto identifierType = m_env->get(node.value());

    if (!identifierType ||
        identifierType.value()->category() == TypeCategory::UserDefined) {
        add_error(node.token(), "undeclared identifier: " + node.value());
        m_result=NULL;
        return true;
    }

    m_result = identifierType.value();
    return true;
}

bool TypeChecker::visit(const ast::TypeExpression& node) {
    auto enum_map = m_env->getEnumMap();
    auto union_map = m_env->getUnionMap();
    if(enum_map.contains(node.value())){
        m_result=enum_map[node.value()];
    }
    else if(union_map.contains(node.value())){
        m_result=union_map[node.value()];
    }
    else if (!identifierToTypeMap.count(node.value())) {
        auto type = m_env->get(node.value());

        if (!type || type.value()->category() != TypeCategory::UserDefined) {
            add_error(node.token(),
                  node.value() + " is not a type"); // return or not return?
        }

        m_result = type.value();
        return true;
    }
    else{
        m_result = identifierToTypeMap[node.value()];
    }
    return true;
}

bool TypeChecker::visit(const ast::ExpressionTuple& node){
    auto items=node.items();
    std::vector<TypePtr> types;
    for(auto& elem:items){
        elem->accept(*this);
        types.push_back(m_result);
    }
    m_result=TypeProducer::multipleReturn(types);
    return true;
}

bool TypeChecker::visit(const ast::TypeTuple& node){
    auto items=node.items();
    std::vector<TypePtr> types;
    for(auto& elem:items){
        elem->accept(*this);
        types.push_back(m_result);
    }
    m_result=TypeProducer::multipleReturn(types);
    return true;
}

bool TypeChecker::visit(const ast::ListTypeExpr& node) {
    node.elemType()->accept(*this);
    auto listType = m_result;
    if(node.size()->type()!=ast::KAstNoLiteral){
        check(node.size(), TypeProducer::integer());
    }
    std::string size="";
    if(node.size()->type()==ast::KAstNoLiteral){
        size = "-1";
    }
    else{
        size = std::dynamic_pointer_cast<ast::IntegerLiteral>(node.size())->value();
    }
    m_result = TypeProducer::list(
        listType,size);
    return true;
}

bool TypeChecker::visit(const ast::FunctionTypeExpr& node) {
    std::vector<TypePtr> parameterTypes;
    auto args=node.argTypes();
    for (auto& param : args) {
        param->accept(*this);
        parameterTypes.push_back(m_result);
    } 
    node.returnTypes()->accept(*this);
    auto returnType = m_result;
    m_result = TypeProducer::function(parameterTypes, returnType);
    return true; 
}

bool TypeChecker::visit(const ast::PointerTypeExpr& node) {
    node.baseType()->accept(*this);
    m_result = TypeProducer::pointer(m_result);
    return true;
}

bool TypeChecker::visit(const ast::NoLiteral& node) {
    m_result = TypeProducer::voidT();
    return true;
}

bool TypeChecker::visit(const ast::IntegerLiteral& node) {
    m_result = TypeProducer::integer();
    return true;
}

bool TypeChecker::visit(const ast::DecimalLiteral& node) {
    m_result = TypeProducer::decimal();
    return true;
}

bool TypeChecker::visit(const ast::StringLiteral& node) {
    m_result = TypeProducer::string();
    return true;
}

bool TypeChecker::visit(const ast::BoolLiteral& node) {
    m_result = TypeProducer::boolean();
    return true;
}

bool TypeChecker::visit(const ast::NoneLiteral& node) {
    m_result = TypeProducer::voidT();
    return true;
}

bool TypeChecker::visit(const ast::UnionLiteral& node) { 
    auto name =identifierName(node.name());
    std::map<std::string, TypePtr> item_map;
    for (auto item : node.elements()) {
        item.first->accept(*this);
        auto item_name=identifierName(item.second);
        if(item_map.contains(item_name)){
            add_error(item.second->token(),item_name+" is already defined as an union member");
        }
        else{
            item_map[item_name]=m_result;
        }
    }
    auto union_map= m_env->getUnionMap();
    if(union_map.contains(name)){
        add_error(node.token(), "Redefination of union: " + name);
    }
    else{
        m_env->add_union(name,types::TypeProducer::unionT(name, item_map));
    }
    return true; 
}

bool TypeChecker::visit(const ast::EnumLiteral& node) {
    auto name=identifierName(node.name());
    std::vector<std::string> values;
    for(auto& elem:node.fields()){
        auto itemName=identifierName(elem.first);
        if(std::count(values.begin(), values.end(), itemName)){
            add_error(elem.first->token(), "Duplicate enum item: " + itemName);
        }
        else{
            values.push_back(itemName);
        }
    }
    auto enum_map= m_env->getEnumMap();
    if(enum_map.contains(name)){
        add_error(node.token(), "Redefination of enum: " + name);
    }
    else{
        m_env->add_enum(name,types::TypeProducer::enumT(name, values));
    }
    return true; 
}

bool TypeChecker::visit(const ast::WithStatement& node) { 
    //TODO: check if the variables are capable of context creation and add them to the environment
    checkBody(node.body());
    return true; 
}

bool TypeChecker::visit(const ast::VirtualStatement& node) { return true; }

bool TypeChecker::visit(const ast::CastStatement& node) {
    node.cast_type()->accept(*this);
    TypePtr castType = m_result;
    node.value()->accept(*this);

    if (!m_result->isCastableTo(*castType)) {
        add_error(node.token(), m_result->stringify() + " can not be casted to " +
                                castType->stringify());
    }

    return true;
}

bool TypeChecker::visit(const ast::DefaultArg& node) { return true; }

bool TypeChecker::visit(const ast::TernaryIf& node) { 
    node.if_value()->accept(*this);
    TypePtr ifType = m_result;
    check(node.if_condition(), TypeProducer::boolean());
    check(node.else_value(), ifType);
    m_result=ifType;
    return true; 
}

bool TypeChecker::visit(const ast::TryExcept& node) { 
    checkBody(node.body());
    if(node.else_body()->type()!=ast::KAstNoLiteral){
        checkBody(node.else_body());
    }
    auto except_clauses = node.except_clauses();
    for(auto except_clause : except_clauses){
        //TODO: Check if the exception is a subclass of the exception in the except block
        auto exception=except_clause.first.first;
        std::vector<std::pair<TypePtr,ast::AstNodePtr>> add_var={};
        if(exception.size()>0){
            exception[0]->accept(*this);
            auto type=m_result;
            for(size_t i=1;i<exception.size();i++){
                check(exception[i],type);
            }
            if(except_clause.first.second->type()!=ast::KAstNoLiteral){
                std::pair<TypePtr,ast::AstNodePtr> var=std::make_pair(type,except_clause.first.second);
                add_var.push_back(var);
            }
        }
        checkBody(except_clause.second,add_var);
    }
    return true; 
}
bool TypeChecker::visit(const ast::MultipleAssign& node){
    auto name=node.names();
    auto value=node.values();
    auto assign_type=ast::MultipleAssign::MultiAssignType::Normal;
    //type and if it is defined before
    std::vector<std::pair<TypePtr,bool>> value_type;
    for(auto& val : value){
        val->accept(*this);
        value_type.push_back(std::make_pair(m_result,true));
    }
    if(value_type.size()>1){
        //this is not a list or function returning multiple stuff
        for(size_t i=0;i<name.size();i++){
            if(name[i]->type()==ast::KAstIdentifier){
                if(defined(name[i])){
                    check(name[i],value_type[i].first);
                }
                else{
                    value_type[i].second=false;
                    m_env->set(identifierName(name[i]), value_type[i].first);
                }
            }
        }
    }
    else{
        auto type=value_type[0].first;
        value_type.clear();
        if(type->category()==List){
            //TODO:add dictionary here
            auto elem_type=std::dynamic_pointer_cast<ListType>(type)->elemType();
            for(size_t i=0;i<name.size();i++){
                value_type.push_back(std::make_pair(elem_type,true));
                if(name[i]->type()==ast::KAstIdentifier){
                    if(defined(name[i])){
                        check(name[i],elem_type);
                    }
                    else{
                        value_type[i].second=false;
                        m_env->set(identifierName(name[i]), elem_type);
                    }
                }
            }
            assign_type=ast::MultipleAssign::MultiAssignType::ListType;
        }
        else if(type->category()==MultipleReturn){
            auto ret_type=std::dynamic_pointer_cast<MultipleReturnType>(type);
            auto ret_types=ret_type->returnTypes();
            if(ret_types.size()>name.size()){
                add_error(node.token(), "To few variables on the left hand side");
            }
            else if(ret_types.size()<name.size()){
                add_error(node.token(), "To many variables on the left hand side");
            }
            else{
                for(size_t i=0;i<name.size();i++){
                    value_type.push_back(std::make_pair(ret_types[i],true));
                    if(name[i]->type()==ast::KAstIdentifier){
                        if(defined(name[i])){
                            check(name[i],ret_types[i]);
                        }
                        else{
                            value_type[i].second=false;
                            m_env->set(identifierName(name[i]), value_type[i].first);
                        }
                    }
                }
            }
            assign_type=ast::MultipleAssign::MultiAssignType::MultipleReturn;
        }
        else{
            add_error(node.token(), "To many variables on the left hand side");
        }
    }
    auto& nonConstNode = const_cast<ast::MultipleAssign&>(node);
    nonConstNode.setProcessedType(value_type);
    nonConstNode.set_assign_type(assign_type);
    return true; 
}
}